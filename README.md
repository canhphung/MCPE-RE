# MCPE 1.1.5 Full Decompilation & Offline Search (local research)

**Target**: the owner's locally acquired Android `libminecraftpe.so` (ARM32, 1.1.5, game protocol 113).

**Scope**: Ghidra auto-analysis + best-effort decompilation of **every function recognized in the binary**, with one JSON record per function. The index supports symbol and pseudocode search for LegacyPE-Server research. This is **not** restoration of the original source code or a byte-identical rebuild. Stripped/undiscovered functions and data are not magically recovered.

**Status**: toolchain source and offline indexer included; tested Python/SQLite offline. Requires Ghidra and the owner's binary to execute full decompilation; no `.so` is distributed.

## Verified supplied binary — immediate symbol search (no Ghidra needed)

An uploaded `libminecraftpe.so` was inspected directly on 2026-11-15:

- SHA256: `3eed76a1659e562bf7a1e5efc6119f179c312d3a46b8ce68454b486ba5ed7ddf`
- ELF32 little-endian ARM / EABI5; 37,980,728 bytes
- `.dynsym`: **63,478 entries** in total, including unnamed entries
- Extracted **63,472 named symbols**, including **55,008 FUNC symbols** (54,609 defined in this shared object)
- Offline `symbols.sqlite` was generated from **this exact uploaded file** using `readelf` + `c++filt`.

Download/use `mcpe-115-symbols.sqlite` beside this toolkit, or regenerate it on your own computer:

```bash
export RE_WORK="$HOME/mcpe-115-re-work"
bash tools/run.sh symbols /path/to/libminecraftpe.so
bash tools/run.sh symsearch 'MobEquipmentPacket'
bash tools/run.sh symsearch 'LegacyClientNetworkHandler'
bash tools/run.sh symshow 00d404e3
bash tools/run.sh symstats
```

**A symbol is not pseudocode.** This ready-made index provides mangled/demangled C++
function names, virtual addresses, sizes and Thumb indicator bits. It does **not**
contain reconstructed functions; running Ghidra export is still required. ELF ARM
Thumb function symbols frequently have bit 0 set (`0x...e3`), whereas Ghidra's
actual instruction address may be even (`0x...e2`). Treat them as virtual
addresses (not raw file offsets).

See `SYMBOL_ANALYSIS.md` for confirmed useful symbol addresses and next steps.

## Requirements

- Linux x86_64, Ghidra (official download: https://github.com/NationalSecurityAgency/ghidra/releases)
- The **matching JDK required by your Ghidra release**; e.g. the current Ghidra 12.2 Getting Started document specifies **JDK 25**. Do not assume Ubuntu 22's default JDK is new enough.
- Python 3.9+ with standard-library `sqlite3` compiled with FTS5 (`sqlite3` from typical Ubuntu installations includes it)
- Disk/RAM: start with 8 GB RAM; 16+ GB RAM and several GB free storage are recommended for this large binary. Actual needs depend on Ghidra analysis and output volume.

### 1. Install the downloaded official Ghidra release

Extract the release zip into `/opt/` or a directory of your choice. Do not guess an artifact URL or unpack the GitHub source tree as if it were a prebuilt release.

```bash
java -version
export GHIDRA_HOME=/opt/ghidra_12.2_PUBLIC   # replace with your ACTUAL installed path
export RE_WORK="$HOME/mcpe-115-re-work"      # private output, outside Git repos
export GHIDRA_MAX_CPU=4                     # conservative on 4 vCPU VPS

# binary was previously stored in the LegacyPE project locally
ls -lh /root/LegacyPE-Server/research-local/libminecraftpe.so
```

### 2. Import and auto-analyze once

```bash
bash tools/run.sh import /root/LegacyPE-Server/research-local/libminecraftpe.so
```

Import creates a persistent Ghidra project at `$RE_WORK/ghidra_projects/MCPE115.gpr`; do **not** delete it. This phase runs Ghidra's analysis, including function discovery and symbol processing. Import can be expensive and may require adjusting memory or analysis options on your machine.

### 3. Smoke test with 100 functions (before committing to full run)

```bash
bash tools/run.sh export 30 100
bash tools/run.sh index
bash tools/run.sh search 'Inventory' 10
bash tools/run.sh status
```

If these fail, inspect `$RE_WORK/logs/export.log` and `$RE_WORK/logs/export-scripts.log` before attempting full export.

### 4. Export ALL known functions

```bash
bash tools/run.sh export 30 0
bash tools/run.sh index
bash tools/run.sh status
```

`30` is the **maximum seconds per function**; `0` means no count limit. Already-exported functions are skipped, so you can run this repeatedly after an interruption. To retry only failed functions:

```bash
bash tools/run.sh export 90 0 retry-errors
bash tools/run.sh index
```

To force re-decompilation of everything (e.g. after improved type reconstruction):

```bash
bash tools/run.sh export 60 0 force
bash tools/run.sh index
```

If you stop the process forcibly, the last JSON entry is atomic; earlier completed files survive. An import interrupted during analysis is a separate issue and might require Ghidra project recovery.

### 5. Agent querying (no context-window dump)

```bash
# Name matching, including C++ namespace separators
python3 tools/query.py --db "$RE_WORK/index.sqlite" names 'ContainerSetContent'
python3 tools/query.py --db "$RE_WORK/index.sqlite" names 'PlayerAction'

# Full-text search by symbol or words in decompiled code
python3 tools/query.py --db "$RE_WORK/index.sqlite" search 'inventory' --limit 20
python3 tools/query.py --db "$RE_WORK/index.sqlite" search 'LevelEvent' --limit 20

# Read exact code for a result (use the Ghidra address printed by search)
python3 tools/query.py --db "$RE_WORK/index.sqlite" show 00123456

# Short commands via wrapper
bash tools/run.sh search 'MobEquipment'
bash tools/run.sh show 00123456
```

`search` uses SQLite FTS5: quote complex terms as needed; `names` is substring search for C++ punctuation like `::`.

**Never feed all pseudocode into a model context.** Have the agent find symbols, inspect small sets of functions, check their callers/callees in Ghidra when needed, record assumptions, then make independent C++ changes with tests.

## Output layout

```text
$RE_WORK/
  binary.sha256
  import_name.txt
  ghidra_projects/
    MCPE115.gpr         # Ghidra project (not for public sharing)
    MCPE115.rep/
  logs/
    import.log
    export.log
  exports/
    functions/
      0a/
        0134bd73.json  # metadata + full decompiled C-like pseudocode
      ff/
        ...
  index.sqlite           # metadata + full-text index (may be large)
```

Each function record has `address`, `name`, `full_name`, `signature`, `bytes_in_body`, `is_thunk`, `status` (`ok` / `timeout` / `error`), `error`, `elapsed_ms`, and `pseudocode`.

**Practical meaning of 'full':** attempt every function Ghidra currently recognizes, including local and thunks. This does not imply every machine-code byte becomes a meaningful function, or that every decompilation succeeds. Improve types/function discovery in the saved Ghidra project and rerun `force` where necessary.

## Verification

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile tools/index.py tools/query.py
bash -n tools/run.sh
```

These checks exercise the *indexing/query layer*, not Ghidra or the actual target binary. Full pipeline execution must happen on your machine containing Ghidra and `libminecraftpe.so`.

## Security and legal

Keep the game binary, raw decompilation exports, APKs, project files, login tokens, packet captures and index **private and outside public repositories**. Deriving an independent protocol or behavior specification is different from redistributing copyrighted game source. Check applicable license/legal requirements before sharing any generated code.

## References

- Ghidra Headless Analyzer: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md
- Ghidra DecompInterface: https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html
- LegacyPE-Server project research: `docs/research/RE-0001_provenance.md`, `RE-0002_packet_ids.md`
