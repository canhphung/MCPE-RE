"""Run using python3 -m unittest discover -s tests -v."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import index


class IndexTests(unittest.TestCase):
    def test_index_search_update_and_incremental(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outputs = root / 'exports' / 'functions' / 'a0'
            outputs.mkdir(parents=True)
            fn = outputs / '001234.json'
            rec = {
                'address': '001234', 'name': 'Inventory::setSlot',
                'full_name': 'Inventory::setSlot',
                'signature': 'void setSlot(int)', 'bytes_in_body': 120,
                'is_thunk': False, 'status': 'ok', 'error': '', 'elapsed_ms': 15,
                'pseudocode': 'void setSlot(int x) { do_inventory_update(x); }'
            }
            fn.write_text(json.dumps(rec), encoding='utf-8')
            db_path = root / 'index.sqlite'
            self.assertEqual((1, 0, 0), index.build(root / 'exports' / 'functions', db_path))
            self.assertEqual((0, 1, 0), index.build(root / 'exports' / 'functions', db_path))
            conn = sqlite3.connect(db_path)
            self.assertEqual(1, conn.execute('select count(*) from functions_fts where functions_fts match "inventory"').fetchone()[0])
            conn.close()
            rec['pseudocode'] = 'void setSlot(int x) { synchronize_held_item(x); }'
            rec['status'] = 'ok'
            fn.write_text(json.dumps(rec), encoding='utf-8')
            self.assertEqual((1, 0, 0), index.build(root / 'exports' / 'functions', db_path))
            conn = sqlite3.connect(db_path)
            self.assertEqual(1, conn.execute('select count(*) from functions_fts where functions_fts match "synchronize_held_item"').fetchone()[0])
            conn.close()


if __name__ == '__main__':
    unittest.main()
