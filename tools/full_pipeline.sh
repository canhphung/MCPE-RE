#!/usr/bin/env bash
set -euo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export RE_WORK="${RE_WORK:-$HOME/mcpe-115-re-work}"
export GHIDRA_HEADLESS_MAXMEM="${GHIDRA_HEADLESS_MAXMEM:-8G}"
: "${GHIDRA_HOME:?Set GHIDRA_HOME to your Ghidra installation}"
[[ -x "$GHIDRA_HOME/support/analyzeHeadless" ]]
[[ -f "$RE_WORK/import_name.txt" ]] || { echo 'Run tools/run.sh import first' >&2; exit 2; }
mkdir -p "$RE_WORK/pipeline" "$RE_WORK/logs"
cd "$ROOT"
exec 9>"$RE_WORK/pipeline/run.lock"
flock -n 9 || { echo 'Another pipeline is active'; exit 1; }
run_export() {
 local seconds="$1" mode="$2" attempt log
 for attempt in 1 2 3; do
  log="$RE_WORK/logs/full-${seconds}-${mode}-$(date -u +%Y%m%dT%H%M%S)-${attempt}.log"
  if "$GHIDRA_HOME/support/analyzeHeadless" "$RE_WORK/ghidra_projects" MCPE115 -process "$(cat "$RE_WORK/import_name.txt")" -noanalysis -readOnly -scriptPath "$ROOT/ghidra_scripts" -postScript ParallelBulkDecompile.java "$RE_WORK/exports/functions" "$seconds" 0 "$mode" > "$log" 2>&1 && rg -q 'PARALLEL_ALL_WORKERS_COMPLETE' "$log"; then
   bash tools/run.sh index
   return 0
  fi
  echo "Interrupted/failed export; preserving atomic JSON; see $log"
 done
 return 1
}
"$GHIDRA_HOME/support/analyzeHeadless" "$RE_WORK/ghidra_projects" MCPE115 -process "$(cat "$RE_WORK/import_name.txt")" -readOnly -noanalysis -scriptPath "$ROOT/ghidra_scripts" -postScript FunctionCensus.java "$RE_WORK/pipeline/functions.tsv" > "$RE_WORK/logs/census.log" 2>&1
run_export 30 skip
if [[ ! -f "$RE_WORK/pipeline/first-pass-summary.json" ]]; then
python3 - <<'BASELINE'
import sqlite3,json,os
from pathlib import Path
w=Path(os.environ['RE_WORK']); c=sqlite3.connect(w/'index.sqlite')
s=dict(c.execute('select status,count(*) from functions group by status'))
f=[dict(zip(['address','full_name','status','error','elapsed_ms'],r)) for r in c.execute("select address,full_name,status,error,elapsed_ms from functions where status!='ok'")]
(w/'pipeline/first-pass-summary.json').write_text(json.dumps({'statuses':s,'failures':f},indent=2))
c.close()
BASELINE
fi
run_export 90 retry-errors
run_export 180 retry-errors
bash tools/run.sh status
python3 "$ROOT/tools/verify_report.py"
printf 'EXPORT_RETRIES_AND_VERIFICATION_COMPLETE\n'
