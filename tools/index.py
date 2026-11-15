#!/usr/bin/env python3
"""Incremental offline SQLite FTS5 index for Ghidra per-function JSON output.

Zero third-party Python dependencies; raw pseudocode stays on the user's machine.
"""
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS functions (
  id INTEGER PRIMARY KEY,
  address TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  full_name TEXT NOT NULL,
  signature TEXT,
  bytes_in_body INTEGER,
  is_thunk INTEGER,
  status TEXT NOT NULL,
  error TEXT,
  elapsed_ms INTEGER,
  file_path TEXT NOT NULL,
  file_mtime_ns INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_functions_status ON functions(status);
CREATE INDEX IF NOT EXISTS idx_functions_name ON functions(name);
CREATE VIRTUAL TABLE IF NOT EXISTS functions_fts
USING fts5(name, full_name, pseudocode, tokenize='unicode61');
"""


def get_connection(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(db_path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=30000")
    db.executescript(SCHEMA)
    return db


def build(export_dir: Path, db_path: Path) -> tuple[int, int, int]:
    if not export_dir.is_dir():
        raise SystemExit(f"No export directory: {export_dir}")
    db = get_connection(db_path)
    upserted = unchanged = broken = 0
    with db:
        for i, path in enumerate(export_dir.rglob('*.json'), 1):
            try:
                stat = path.stat()
                file_path = str(path.resolve())
                old = db.execute(
                    "SELECT id, file_mtime_ns FROM functions WHERE file_path=?", (file_path,)
                ).fetchone()
                if old and old[1] == stat.st_mtime_ns:
                    unchanged += 1
                    continue
                data = json.loads(path.read_text(encoding="utf-8"))
                address = str(data['address'])
                name = str(data.get('name', ''))
                full_name = str(data.get('full_name', name))
                pseudocode = str(data.get('pseudocode') or '')
                row = db.execute(
                    "SELECT id FROM functions WHERE address=?", (address,)
                ).fetchone()
                if row:
                    id_ = row[0]
                    db.execute("DELETE FROM functions_fts WHERE rowid=?", (id_,))
                    db.execute("""UPDATE functions SET
                        name=?, full_name=?, signature=?, bytes_in_body=?, is_thunk=?,
                        status=?, error=?, elapsed_ms=?, file_path=?, file_mtime_ns=?
                        WHERE id=?""", (
                        name, full_name, str(data.get('signature') or ''),
                        int(data.get('bytes_in_body') or 0), int(bool(data.get('is_thunk'))),
                        str(data.get('status', 'unknown')), str(data.get('error') or ''),
                        int(data.get('elapsed_ms') or 0), file_path, stat.st_mtime_ns, id_
                    ))
                else:
                    cur = db.execute("""INSERT INTO functions(
                        address, name, full_name, signature, bytes_in_body, is_thunk,
                        status, error, elapsed_ms, file_path, file_mtime_ns)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (
                        address, name, full_name, str(data.get('signature') or ''),
                        int(data.get('bytes_in_body') or 0), int(bool(data.get('is_thunk'))),
                        str(data.get('status', 'unknown')), str(data.get('error') or ''),
                        int(data.get('elapsed_ms') or 0), file_path, stat.st_mtime_ns
                    ))
                    id_ = cur.lastrowid
                db.execute(
                    "INSERT INTO functions_fts(rowid,name,full_name,pseudocode) VALUES (?,?,?,?)",
                    (id_, name, full_name, pseudocode)
                )
                upserted += 1
                if upserted % 2000 == 0:
                    db.commit()
            except (OSError, ValueError, KeyError, sqlite3.Error) as exc:
                broken += 1
                print(f"Skipping invalid export {path}: {exc}", file=sys.stderr)
    db.close()
    return upserted, unchanged, broken


def status(export_dir: Path, db_path: Path) -> None:
    if db_path.exists():
        db = sqlite3.connect(db_path)
        print("Indexed functions:")
        for s, count in db.execute("SELECT status,COUNT(*) FROM functions GROUP BY status ORDER BY status"):
            print(f"  {s:<12} {count:,}")
        print(f"  {'TOTAL':<12} {db.execute('SELECT COUNT(*) FROM functions').fetchone()[0]:,}")
        db.close()
    else:
        print("No index yet; run: tools/run.sh index")
    print(f"Export JSON files: {sum(1 for _ in export_dir.rglob('*.json')):,}")


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in {'build', 'status'}:
        raise SystemExit('Usage: index.py build|status <export_dir> <index.sqlite>')
    export_path, database_path = map(Path, sys.argv[2:])
    if sys.argv[1] == 'build':
        result = build(export_path, database_path)
        print(f'Indexed/updated: {result[0]:,}; unchanged: {result[1]:,}; broken: {result[2]:,}')
    else:
        status(export_path, database_path)
