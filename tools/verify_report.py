import collections, datetime, hashlib, json, sqlite3, subprocess, os
from pathlib import Path
root=Path(__file__).resolve().parents[1]
w=Path(os.environ.get('RE_WORK', str(Path.home()/'mcpe-115-re-work'))).resolve()
expected={line.split('\t')[0] for line in (w/'pipeline/functions.tsv').read_text().splitlines()}
records={}; broken=[]; empty=[]; warnings=0
for p in (w/'exports/functions').rglob('*.json'):
 try:
  d=json.loads(p.read_text()); a=d['address']
  if a in records: raise ValueError('duplicate address')
  records[a]=d
  if d['status']=='ok' and not d.get('pseudocode','').strip(): empty.append(a)
  if d['status']=='ok' and any(x in d.get('pseudocode','') for x in ['WARNING:', '/* WARNING']): warnings+=1
 except Exception as e: broken.append({'file':str(p),'error':str(e)})
missing=sorted(expected-records.keys()); extra=sorted(records.keys()-expected)
counts=dict(collections.Counter(d['status'] for d in records.values()))
c=sqlite3.connect(w/'index.sqlite'); c.row_factory=sqlite3.Row
integrity=c.execute('pragma integrity_check').fetchone()[0]
c.execute("INSERT INTO functions_fts(functions_fts) VALUES('integrity-check')")
indexed={r[0] for r in c.execute('select address from functions')}
fts_count=c.execute('select count(*) from functions_fts').fetchone()[0]
assert integrity=='ok' and indexed==set(records) and fts_count==len(records)
assert not missing and not extra and not broken and not empty
checks={}
for topic,term in {'inventory':'Inventory','blocks':'Block','animation':'Animation','entity_ai':'Goal','world_generation':'Biome'}.items():
 hits=c.execute('select count(*) from functions_fts where functions_fts match ?',('"'+term+'"',)).fetchone()[0]
 sample=c.execute("select address,full_name,file_path from functions where status='ok' and full_name like ? and is_thunk=0 and bytes_in_body>=64 order by bytes_in_body desc limit 1",('%'+term+'%',)).fetchone()
 assert hits>0 and sample is not None,(topic,hits)
 d=json.loads(Path(sample['file_path']).read_text());assert d['pseudocode'].strip()
 subprocess.run(['python3',str(root/'tools/query.py'),'--db',str(w/'index.sqlite'),'show',sample['address']],check=True,stdout=subprocess.DEVNULL)
 subprocess.run(['python3',str(root/'tools/query.py'),'--db',str(w/'index.sqlite'),'search',term,'--limit','1'],check=True,stdout=subprocess.DEVNULL)
 subprocess.run(['python3',str(root/'tools/query.py'),'--db',str(w/'index.sqlite'),'names',term,'--limit','1'],check=True,stdout=subprocess.DEVNULL)
 checks[topic]={'fts_hits':hits,'sample_address':sample['address'],'sample_name':sample['full_name']}
failures=[{k:d.get(k) for k in ['address','full_name','status','error','elapsed_ms']} for d in records.values() if d['status']!='ok']
(w/'failures.json').write_text(json.dumps(failures,indent=2))
sha=hashlib.file_digest((w/'libminecraftpe.so').open('rb'),'sha256').hexdigest()
assert sha=='3eed76a1659e562bf7a1e5efc6119f179c312d3a46b8ce68454b486ba5ed7ddf'
baseline=json.loads((w/'pipeline/first-pass-summary.json').read_text())
result={'first_pass_statuses':baseline['statuses'],'generated_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'binary_sha256':sha,'discovered_internal_functions':len(expected),'exports':len(records),'statuses':counts,'thunks':sum(d['is_thunk'] for d in records.values()),'successful_pseudocode_with_warning':warnings,'missing':missing,'unexpected':extra,'broken':broken,'empty_success':empty,'sqlite_integrity':integrity,'indexed':len(indexed),'fts_rows':fts_count,'checks':checks,'failures':failures}
(w/'analysis-summary.json').write_text(json.dumps(result,indent=2))
lines=['# MCPE 1.1.5 decompilation report','',f"Generated UTC: {result['generated_utc']}",'',f'Binary SHA256: `{sha}`','Architecture: ELF32 little-endian ARM, EABI5, stripped Android shared object.','Tools: Ghidra 12.2 PUBLIC, Temurin JDK 25.0.5+8; Python SQLite FTS5.','',f'- Discovered internal functions: {len(expected):,}',f'- Exported records: {len(records):,}',f'- Status counts: {counts}',f"- Thunks included: {result['thunks']:,}",f'- Successful pseudocode containing warning comments: {warnings:,}','- Missing addresses, duplicate/invalid JSON, empty successful pseudocode: 0',f'- SQLite integrity: {integrity}; indexed functions and FTS rows: {len(indexed):,}','', '## Retry history','',f"First pass: {baseline['statuses']}. Retried unsuccessful functions at 90 seconds / at least 500,000 instructions, then 180 seconds / at least 1,000,000 instructions, with payload limit at least 128 MB. See logs/full-* for per-worker outcomes.",'', '## Validation','', 'Compared the exact Ghidra function address set with all JSON and index addresses. Each category below passed CLI function-name lookup, full-text search and pseudocode retrieval.','']
for topic,d in checks.items(): lines.append(f"- {topic}: {d['fts_hits']:,} FTS matches; example `{d['sample_address']}` — {d['sample_name']}")
lines+=['','## Remaining gaps','', 'Complete means every internal function currently recognized by this saved Ghidra project was attempted; it does not establish recovery of all machine code or original source. Ghidra analysis logged local disassembly, pcode, function-body and address-space warnings. External Android libraries are absent (402 unresolved external symbols during import). Stripped symbols, indirect calls, inferred types and control flow can remain incomplete. Successful output can still contain warning comments and inaccurate pseudocode. External namespace/PLT thunks counted as internal by the Ghidra API are included; no claim of decompiling external library implementations.','',f'Failed or timed-out functions after retries: {len(failures)}; details in failures.json.','No LegacyPE-Server code was changed; user excluded that work.','','## Reproduce / resume','', 'Run `bash tools/full_pipeline.sh`. It runs four independent DecompInterface workers over disjoint address groups, locks against concurrent writers, resumes from atomic per-function JSON, retries process interruption up to three times per phase, retries errors at 90 and 180 seconds, and rebuilds the index after each completed phase. A persistent failure stops with logs and retains outputs; rerunning resumes. Then run `python3 tools/verify_report.py`.','', 'Set GHIDRA_HOME and RE_WORK for your machine; run queries from the toolkit checkout using tools/run.sh. Keep all binary, JSON, databases, Ghidra state and reports private outside public checkouts. No public commits or publication were performed.','']
(w/'ANALYSIS_REPORT.md').write_text('\n'.join(lines))
c.commit();c.execute('pragma wal_checkpoint(truncate)');c.close()
print(json.dumps({k:v for k,v in result.items() if k not in ['failures','checks']},indent=2))
