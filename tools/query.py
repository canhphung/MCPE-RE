#!/usr/bin/env python3
"""Offline agent-facing search & retrieval CLI for the MCPE 1.1.5 RE index."""
import argparse
import json
import sqlite3
from pathlib import Path


def db_connect(path: Path):
    if not path.is_file():
        raise SystemExit(f"Index not found: {path} (run: tools/run.sh index)")
    db = sqlite3.connect(f'file:{path.resolve()}?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    return db


def search(db, query: str, limit: int) -> None:
    try:
        rows = db.execute("""
            SELECT f.address, f.name, f.full_name, f.status, f.bytes_in_body,
                   snippet(functions_fts, 2, '[', ']', '...', 12) AS excerpt
            FROM functions_fts JOIN functions f ON f.id=functions_fts.rowid
            WHERE functions_fts MATCH ?
            ORDER BY bm25(functions_fts, 5, 6, 1) LIMIT ?
        """, (query, limit)).fetchall()
    except sqlite3.OperationalError as exc:
        raise SystemExit(f'Invalid FTS5 syntax: {exc}; try quoted terms: "{query}"')
    if not rows:
        print('No matches. Try a shorter token or the `names` subcommand.')
    for row in rows:
        print(f"{row['address']}  {row['full_name']}  ({row['status']}, {row['bytes_in_body']} bytes)")
        excerpt = (row['excerpt'] or '').strip().replace('\n', ' ')
        if excerpt:
            print('    ' + excerpt[:240])


def names(db, query: str, limit: int) -> None:
    # Useful for C++ symbols with ::, special operator names and quoted templates.
    rows = db.execute("""
        SELECT address,full_name,status,bytes_in_body FROM functions
        WHERE lower(full_name) LIKE ? ORDER BY bytes_in_body DESC LIMIT ?
    """, ('%' + query.lower() + '%', limit))
    for row in rows:
        print(f"{row['address']}  {row['full_name']}  ({row['status']}, {row['bytes_in_body']} bytes)")


def show(db, identity: str) -> None:
    row = db.execute('SELECT * FROM functions WHERE address=?', (identity,)).fetchone()
    if row is None:
        matches = db.execute('SELECT * FROM functions WHERE full_name LIKE ? LIMIT 3',
                             ('%' + identity + '%',)).fetchall()
        if not matches:
            raise SystemExit('No function found. Try search or names.')
        if len(matches) != 1:
            print('Ambiguous name; use an exact address:')
            for match in matches:
                print(f"{match['address']} {match['full_name']}")
            raise SystemExit(2)
        row = matches[0]
    data = json.loads(Path(row['file_path']).read_text(encoding='utf-8'))
    print(f"// {data['full_name']} @ {data['address']}  status={data['status']}")
    print(f"// Signature: {data.get('signature', '')}")
    if data.get('error'):
        print('// Error: ' + data['error'])
    print(data.get('pseudocode') or '// No pseudocode available')


def main():
    parser = argparse.ArgumentParser(description='Search decompiled MCPE 1.1.5 functions')
    parser.add_argument('--db', type=Path, default=Path.home() / 'mcpe-115-re-work' / 'index.sqlite')
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('search', 'names'):
        p = sub.add_parser(command)
        p.add_argument('query')
        p.add_argument('--limit', type=int, default=20)
    p = sub.add_parser('show')
    p.add_argument('identity', help='Exact Ghidra address, or unique substring of name')
    args = parser.parse_args()
    db = db_connect(args.db)
    if args.command == 'search':
        search(db, args.query, args.limit)
    elif args.command == 'names':
        names(db, args.query, args.limit)
    else:
        show(db, args.identity)
    db.close()


if __name__ == '__main__':
    main()
