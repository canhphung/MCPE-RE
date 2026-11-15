#!/usr/bin/env python3
"""Build/query an index of exported ELF dynamic symbols without Ghidra.

This is *not* pseudocode: it records symbol names, addresses and sizes. The
index is useful before bulk decompilation has run and doesn't include binaries.
Requires: readelf, c++filt, Python 3 sqlite3 with FTS5.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys

LINE_RE = re.compile(r'^\s*(\d+):\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$')
SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS symbols (
  symbol_number INTEGER PRIMARY KEY,
  address TEXT NOT NULL,
  value INTEGER NOT NULL,
  size INTEGER NOT NULL,
  sym_type TEXT NOT NULL,
  binding TEXT NOT NULL,
  visibility TEXT NOT NULL,
  section TEXT NOT NULL,
  raw_name TEXT NOT NULL,
  demangled TEXT NOT NULL,
  defined INTEGER NOT NULL,
  thumb INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_symbols_address ON symbols(value);
CREATE INDEX IF NOT EXISTS idx_symbols_type ON symbols(sym_type);
CREATE INDEX IF NOT EXISTS idx_symbols_defined ON symbols(defined);
CREATE VIRTUAL TABLE IF NOT EXISTS symbols_fts
  USING fts5(raw_name, demangled, tokenize='unicode61');
"""


def symbols_from_binary(path: Path):
    if not path.is_file():
        raise SystemExit(f'ELF file not found: {path}')
    result = subprocess.run(['readelf', '-W', '--dyn-syms', str(path)],
                            check=True, capture_output=True, text=True)
    rows = []
    for line in result.stdout.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        n, val, size, sym_type, binding, vis, section, name = m.groups()
        # Version labels after the first whitespace are readelf annotations.
        name = name.split(' ', 1)[0]
        if not name:
            continue
        value = int(val, 16)
        rows.append((int(n), f'{value:08x}', value, int(size),
                     sym_type, binding, vis, section, name))
    if not rows:
        raise SystemExit('readelf returned no named symbols')
    # One demangler subprocess for the full symbol table (rather than 60k forks).
    raw_names = [r[-1] for r in rows]
    proc = subprocess.run(['c++filt', '-n'], input='\n'.join(raw_names) + '\n',
                          capture_output=True, text=True, check=True)
    demangled_names = proc.stdout.splitlines()
    if len(demangled_names) != len(rows):
        raise SystemExit('c++filt returned a different number of names')
    for row, demangled in zip(rows, demangled_names):
        n, addr, value, size, typ, bind, vis, section, raw = row
        yield (n, addr, value, size, typ, bind, vis, section, raw, demangled,
               int(section != 'UND'), int(typ == 'FUNC' and (value & 1) == 1))


def fingerprint(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def build(path: Path, db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(db_path)
    db.executescript(SCHEMA)
    rows = list(symbols_from_binary(path))
    sha = fingerprint(path)
    with db:
        db.execute('DELETE FROM symbols_fts')
        db.execute('DELETE FROM symbols')
        db.executemany('''INSERT INTO symbols
          (symbol_number,address,value,size,sym_type,binding,visibility,section,
           raw_name,demangled,defined,thumb) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''', rows)
        db.executemany('INSERT INTO symbols_fts(rowid,raw_name,demangled) VALUES(?,?,?)',
                       ((r[0], r[8], r[9]) for r in rows))
        for k, v in [('binary_sha256', sha), ('binary_size', str(path.stat().st_size)),
                     ('source', 'readelf --dyn-syms + c++filt'),
                     ('pseudocode_available', 'no; Ghidra export must run separately')]:
            db.execute('INSERT OR REPLACE INTO metadata(key,value) VALUES(?,?)', (k,v))
    db.execute('PRAGMA optimize')
    db.close()
    print(f'Indexed {len(rows):,} named dynamic symbols from {path}')
    print(f'SHA256 {sha}')
    print(f'Database {db_path}')


def read_only_db(path: Path):
    if not path.exists():
        raise SystemExit(f'Symbol index not found: {path}; run build first')
    db = sqlite3.connect(f'file:{path.resolve()}?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    return db


def search(db, term: str, limit: int, output_json: bool) -> None:
    # LIKE handles partial names and C++ syntax (::, <>, etc).
    rows = db.execute('''SELECT address,size,sym_type,defined,thumb,raw_name,demangled
         FROM symbols WHERE raw_name LIKE ? OR demangled LIKE ?
         ORDER BY defined DESC, (sym_type='FUNC') DESC, size DESC LIMIT ?''',
         ('%' + term + '%', '%' + term + '%', limit)).fetchall()
    if output_json:
        print(json.dumps([dict(r) for r in rows], ensure_ascii=False, indent=2))
    else:
        for r in rows:
            print(f"{r['address']} [{r['sym_type']:<6} {r['size']:>6}B] "
                  f"{r['demangled']}")
        if not rows:
            print('No matches (searches exported dynamic symbols only).')


def show(db, address: str) -> None:
    try:
        numeric = int(address, 16)
    except ValueError:
        raise SystemExit('Address must be hex, e.g. 0134bd73')
    rows = db.execute('''SELECT * FROM symbols WHERE value IN (?,?)
         ORDER BY size DESC LIMIT 30''', (numeric, numeric ^ 1)).fetchall()
    if not rows:
        raise SystemExit('No exported dynamic symbol at that address')
    for r in rows:
        print(json.dumps(dict(r), ensure_ascii=False, indent=2))


def stats(db) -> None:
    print('Binary identity:')
    for r in db.execute('SELECT key,value FROM metadata ORDER BY key'):
        print(f'  {r["key"]}: {r["value"]}')
    print('Dynamic symbols:')
    for r in db.execute('''SELECT sym_type, COUNT(*) count,
        SUM(CASE WHEN defined THEN 1 ELSE 0 END) defined
        FROM symbols GROUP BY sym_type ORDER BY count DESC'''):
        print(f'  {r["sym_type"]:8}: {r["count"]:>7,} total, {r["defined"]:>7,} defined')
    print('Note: dynamic symbols != all functions; no pseudocode generated yet.')


def main() -> None:
    parser = argparse.ArgumentParser(description='Offline MCPE 1.1.5 ELF symbol index')
    parser.add_argument('--db', type=Path,
                        default=Path.home() / 'mcpe-115-re-work' / 'symbols.sqlite')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('build', help='Index dynamic symbols from the .so')
    p.add_argument('elf', type=Path)
    p = sub.add_parser('search', help='Case-insensitive substring search')
    p.add_argument('term')
    p.add_argument('--limit', type=int, default=25)
    p.add_argument('--json', action='store_true')
    p = sub.add_parser('show', help='Look up a symbol by hex address')
    p.add_argument('address')
    sub.add_parser('stats')
    args = parser.parse_args()
    if args.command == 'build':
        build(args.elf, args.db)
        return
    db = read_only_db(args.db)
    try:
        if args.command == 'search':
            search(db, args.term, max(1, min(500, args.limit)), args.json)
        elif args.command == 'show':
            show(db, args.address)
        else:
            stats(db)
    finally:
        db.close()


if __name__ == '__main__':
    main()
