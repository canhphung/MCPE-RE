#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${RE_WORK:-${HOME}/mcpe-115-re-work}"
PROJECT_HOME="$WORK/ghidra_projects"
PROJECT_NAME="MCPE115"
BINARY_FILE="$WORK/import_name.txt"
EXPORT_DIR="$WORK/exports/functions"
DB="$WORK/index.sqlite"
SYMBOL_DB="$WORK/symbols.sqlite"
mkdir -p "$WORK" "$PROJECT_HOME" "$WORK/logs" "$EXPORT_DIR"

usage() {
  cat <<USAGE
Usage: GHIDRA_HOME=/path/to/ghidra RE_WORK=/path/to/work tools/run.sh COMMAND ...

  import  /absolute/path/libminecraftpe.so   Ghidra initial analysis (once)
  export [timeout_seconds=30] [max_new=0] [skip|retry-errors|force]
                                           Export all functions; resumable
  symbols /absolute/path/libminecraftpe.so Build ELF symbol index without Ghidra
  symsearch "Inventory" [limit=20]         Search demangled ELF symbols
  symshow <hex-address>                    View ELF symbol metadata
  symstats                                 Summary of indexed ELF symbols
  index                                    Incrementally index into SQLite FTS5
  status                                   Counts from current JSON exports / index
  search "Inventory" [limit=20]             Search names + pseudocode
  show <address-or-name>                    Print function pseudocode
  help                                     This help

Work directory stays outside any public git repository by default.
USAGE
}

require_ghidra() {
  if [[ -z "${GHIDRA_HOME:-}" ]]; then
    echo 'Set GHIDRA_HOME to your extracted Ghidra install directory' >&2; exit 2
  fi
  HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"
  [[ -x "$HEADLESS" ]] || { echo "Missing executable: $HEADLESS" >&2; exit 2; }
}

cmd="${1:-help}"; shift || :
case "$cmd" in
  import)
    require_ghidra
    binary="${1:?Need binary path}"
    [[ -f "$binary" ]] || { echo "Binary not found: $binary" >&2; exit 2; }
    base="$(basename "$binary")"
    if [[ -f "$BINARY_FILE" ]]; then
      echo "Project already initialized. To avoid overwriting analysis, use another RE_WORK." >&2
      exit 2
    fi
    echo "[MCPE-RE] Checking binary: $binary"
    file "$binary"
    sha256sum "$binary" | tee "$WORK/binary.sha256"
    echo "$base" > "$BINARY_FILE"
    "$HEADLESS" "$PROJECT_HOME" "$PROJECT_NAME" \
       -import "$binary" -max-cpu "${GHIDRA_MAX_CPU:-4}" \
       -log "$WORK/logs/import.log" -scriptlog "$WORK/logs/import-scripts.log" || {
         rm -f "$BINARY_FILE"
         echo "Import failed; inspect $WORK/logs/import.log" >&2
         exit 1
       }
    echo "[MCPE-RE] Initial analysis saved; run: $0 export 30 100"
    ;;
  export)
    require_ghidra
    [[ -f "$BINARY_FILE" ]] || { echo "Run import first" >&2; exit 2; }
    timeout="${1:-30}"
    maxnew="${2:-0}"
    mode="${3:-skip}"
    [[ "$timeout" =~ ^[0-9]+$ && "$maxnew" =~ ^[0-9]+$ ]] || { echo "Timeout and maxnew must be integers" >&2; exit 2; }
    case "$mode" in skip|retry-errors|force) ;; *) echo "Invalid mode" >&2; exit 2 ;; esac
    "$HEADLESS" "$PROJECT_HOME" "$PROJECT_NAME" \
       -process "$(cat "$BINARY_FILE")" -noanalysis -readOnly \
       -scriptPath "$ROOT/ghidra_scripts" \
       -postScript BulkDecompile.java "$EXPORT_DIR" "$timeout" "$maxnew" "$mode" \
       -log "$WORK/logs/export.log" -scriptlog "$WORK/logs/export-scripts.log"
    echo "[MCPE-RE] JSON exports are in $EXPORT_DIR"
    ;;
  symbols)
    binary="${1:?Need binary path}"
    python3 "$ROOT/tools/symbol_index.py" --db "$SYMBOL_DB" build "$binary"
    ;;
  symsearch)
    q="${1:?Need search term}"
    limit="${2:-20}"
    python3 "$ROOT/tools/symbol_index.py" --db "$SYMBOL_DB" search "$q" --limit "$limit"
    ;;
  symshow)
    a="${1:?Need hexadecimal address}"
    python3 "$ROOT/tools/symbol_index.py" --db "$SYMBOL_DB" show "$a"
    ;;
  symstats)
    python3 "$ROOT/tools/symbol_index.py" --db "$SYMBOL_DB" stats
    ;;
  index)
    python3 "$ROOT/tools/index.py" build "$EXPORT_DIR" "$DB"
    ;;
  status)
    python3 "$ROOT/tools/index.py" status "$EXPORT_DIR" "$DB"
    ;;
  search)
    q="${1:?Need search phrase}"
    limit="${2:-20}"
    python3 "$ROOT/tools/query.py" --db "$DB" search "$q" --limit "$limit"
    ;;
  show)
    term="${1:?Need address or function name}"
    python3 "$ROOT/tools/query.py" --db "$DB" show "$term"
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage >&2; exit 2
    ;;
esac
