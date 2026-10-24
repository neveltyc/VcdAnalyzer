<p align="center">
  <h1 align="center">VCD Analyzer</h1>
  <p align="center">
    A fast, single-file CLI for inspecting Verilog <b>VCD</b> waveforms &mdash;
    built for RTL debug, agent workflows, and anyone who wants answers without opening a waveform viewer.
  </p>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.6.0-3366cc?style=flat-square">
  <img alt="Python" src="https://img.shields.io/badge/python-3.9+-3366cc?style=flat-square&logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-3366cc?style=flat-square">
</p>

---

## Why VCD Analyzer?

You have a giant `.vcd` dump from simulation and you need to know what happened to `state[3:0]`
between 17.3 us and 17.6 us. Opening GTKWave means waiting for the GUI, clicking through the
hierarchy, zooming in, squinting at values. This tool gives you the answer in one command.

It is also designed from the ground up for **agent-assisted workflows**: every command has a
`--json` mode that emits compact, machine-readable output so LLM agents can inspect waveforms
without a GUI.

For giant dumps (GB-scale) the full variant adds an **index sidecar**: a one-time
`index` build (~0.2% of the file) turns point queries that would scan the whole
file for minutes into sub-second lookups — built for you in the background while
you keep working.

```bash
python vcd_analyzer.py search sim.vcd --condition "state=5" --show data,valid --begin 17us
```

## Quick start

```bash
# What's in this file?
python vcd_analyzer.py info sim.vcd

# Show me the clock and reset
python vcd_analyzer.py list sim.vcd --filter clk,rst

# What happened between 100 ns and 200 ns?
python vcd_analyzer.py dump sim.vcd --begin 100ns --end 200ns --filter state

# When was valid=1 AND ready=1 at the same time?
python vcd_analyzer.py search sim.vcd --condition "valid=1,ready=1" --show data

# When did req transition while ready was low?
python vcd_analyzer.py search sim.vcd --condition "changed(req),ready=0" --show state

# When did ANY of several channels handshake? (repeat --condition to OR)
python vcd_analyzer.py search sim.vcd --condition "ch0_valid=1,ch0_ready=1" \
                                      --condition "ch1_valid=1,ch1_ready=1"

# Give me a snapshot at exactly 17.55 us
python vcd_analyzer.py snapshot sim.vcd --at 17.55us --filter state,init_done

# Any signal change count, static vs active?
python vcd_analyzer.py summary sim.vcd --filter dll_*

# Index a 10 GB dump once; every later query is instant (full variant)
python vcd_analyzer.py index sim.vcd
```

## Install: full or lite

Two single files, no dependencies, Python 3.9+.

| | **full** — `vcd_analyzer.py` (default) | **lite** — `vcd_analyzer_lite.py` |
|:--|:--|:--|
| Seven query commands, output and semantics | identical | identical |
| Index sidecar acceleration for huge dumps | ✅ built and used automatically | ❌ `index` answers with a pointer to the full file |
| Native multi-core index builder | ✅ embedded (arm64/x86-64 Linux, arm64 macOS, x86-64 Windows) | pure Python only |
| File size | ~1.6 MB | ~180 KB |
| Requirements | Python 3.9+ (Linux needs glibc ≥ 2.17) | Python 3.9+ |

```bash
# Latest (full)
curl -fsSL https://raw.githubusercontent.com/neveltyc/VcdAnalyzer/main/vcd_analyzer.py -o vcd_analyzer.py

# Pinned published release tag (recommended — avoids compatibility surprises from main)
curl -fsSL https://raw.githubusercontent.com/neveltyc/VcdAnalyzer/v1.6.0/vcd_analyzer.py -o vcd_analyzer.py

# Lite (pure Python, no index feature)
curl -fsSL https://raw.githubusercontent.com/neveltyc/VcdAnalyzer/v1.6.0/vcd_analyzer_lite.py -o vcd_analyzer_lite.py

python vcd_analyzer.py --version
```

No pip, no venv, no PyPI. Works anywhere curl and Python 3.9+ are available — CI containers, EDA servers, Docker builds, agent toolchains.

## Commands

| Command | What it does |
|:--------|:-------------|
| `info` | Timescale, signal count, time span, scopes &mdash; the file at a glance |
| `list` | Enumerate signals with path, width, and type |
| `dump` | Print every value change in a time window, in order |
| `summary` | Per-signal stats: active/static, change count, rise/fall edges |
| `snapshot` | What are all known signal values at time T? |
| `compare` | What changed between T1 and T2? |
| `search` | Find intervals where conditions hold, optionally watching related signals |
| `index` | Build the optional `.vcidx` sidecar that makes point queries instant on huge dumps (full variant) |

All commands accept `--begin` / `--end` time windows with unit suffixes (`fs`, `ps`, `ns`, `us`, `ms`, `s`),
`--filter` with substring or glob patterns, and `--json` for structured output.

Run `python vcd_analyzer.py --help` for the full reference.

## JSON output

Every command emits compact structured JSON under `--json`. Agents and scripts
get raw tick counts (`_ticks`) alongside human-readable times (`_h`).

```bash
python vcd_analyzer.py --json info sim.vcd
python vcd_analyzer.py --json search sim.vcd --condition "state=5" --show data
```

## The index sidecar (full variant)

- **Explicit or automatic.** `vcd_analyzer.py index sim.vcd` builds `sim.vcd.vcidx`
  (a fraction of a percent of the source; seconds for a 10 GB dump). Or do
  nothing: the first query on a big unindexed dump starts a background build —
  the next query is fast.
- **Queries use it automatically** whenever the sidecar is fresh; output is
  identical, only faster (minutes-long point lookups become sub-second).
- **Freshness is `(size, mtime_ns)`** recorded in the sidecar header — O(1) per
  query, no content hashing. A stale sidecar warns once and the plain parser
  answers; an automatic rebuild is skipped (with a message) while the source
  looks still-open-for-write (mtime < 5 s, an `lsof` holder, or a Windows
  sharing violation).
- On platforms without an embedded native builder, automatic builds are off
  by default (they would only run the much slower pure-Python pass) — the
  `index` command still works there and says which mechanism it used.
- Environment: `VCD_ANALYZER_AUTO_INDEX=0` disables background builds,
  `VCD_ANALYZER_NO_INDEX=1` disables index use entirely,
  `VCD_ANALYZER_INDEX_THREADS=N` caps the native build threads (default
  min(4, cores)).
- The lite variant has none of this and says so explicitly.

## Semantics notes

- **Multiple value changes per timestamp are preserved.** The IEEE 1364 grammar
  allows several value changes to the same signal within one timestamp
  (delta-cycle style writers); `dump` shows all of them in order and `summary`
  counts each transition. A record that only re-asserts a signal's current
  value — a consecutive duplicate, or a `$dumpall`/`$dumpon` checkpoint
  re-emitting the current value — is a no-op and adds no change event (so
  `summary` static/active accounting stays exact).
- **Bit-exploded buses change once per tick.** When several bits of a
  reassembled bus change at the same timestamp, `dump`, `summary` and
  `changed()` see one assembled value, never cross-bit intermediates. A bit
  written twice in one tick is still a delta-cycle step and stays visible.
- **Vector values are compared at full width.** `b11` and `b0011` on a 4-bit
  signal are the same value (IEEE 1364 left-extension), so re-spelling a value
  is not a change.
- **`summary` counts like `changed()`.** A signal's first observation is not
  a change: a signal first seen inside the window takes that value as `init`
  and reports `defined_at`. Event variables count every trigger.
- **Times are exact.** Text output prints every tick digit (`17.534712ms`);
  a time argument that is not a whole number of ticks is rounded and a warning
  goes to stderr. A missing or unparseable `$timescale` falls back to 1ps with
  a stderr warning.
- **`search` conditions are AND clauses; repeating `--condition` ORs them.**
  One `--condition` is a comma-separated AND list of `SIG=VAL`, `SIG!=VAL`, or
  `changed(SIG)` terms. Repeat the flag and the search holds wherever *any*
  clause holds (OR-of-ANDs) — one clause per channel to find when any
  handshakes. There is no in-string OR: `|` and `OR` inside a condition are
  ordinary text and are rejected, so a mis-typed boolean is an error rather
  than a confident empty result.
- **`changed(SIG)` is an edge predicate**, true at exactly the ticks where SIG
  transitions, and it switches `search` to event mode (instants instead of
  intervals). Every clause must then carry one, or none may. Level terms in
  the clause read the tick's **settled** state, so the answer never depends on
  the order same-tick records happen to be written in; the transitioning
  signal itself reads the value it took **at that edge**, so
  `"changed(s),s=1"` means "rising edge of s". `changed(a),changed(b)` asks for
  both to transition on one tick.
- **Condition matching follows a signal's declared type.** A real/realtime
  signal is compared numerically (`dac=3.14`, `dac=100`), never as a bit
  string — its `%g` text would otherwise read as binary, making `dac=4` match
  a real 100.0. An event variable has no level, so `ev=1` is refused with a
  pointer to `changed(ev)`.
- **Search time windows.** With no `--end`, the effective end is the file's last
  timestamp, and a `--begin` past it is an error. With an explicit `--end`
  beyond the last timestamp, the last known state is extended into the window
  (the same last-known-value persistence used by `snapshot`/`compare`).

## Single file, zero dependencies

`vcd_analyzer.py` is pure Python with no third-party imports. No pip install, no virtualenv
ritual &mdash; drop it anywhere with Python 3.9+ and it works.

## Project layout

```
src/                  Source modules — edit here (Parts 1-9, see _make.py)
_make.py              Assembler: builds both release files from src/ (--check verifies)
vcd_analyzer.py       Release artifact: FULL variant (generated; do not edit)
vcd_analyzer_lite.py  Release artifact: LITE variant, pure Python (generated)
native/               Rust index-builder crate + cross-build script (cargo-zigbuild)
verify/               pytest + unittest test suite
verify/fixtures/      Sanitized VCD waveforms (no private paths)
verify/samples/       Real-world GitHub VCD fixtures for smoke testing
.github/workflows/    CI: both release files must match src/, tests on 3.9-3.13
CHANGELOG.md          Compact changelog with links to detailed release notes
```

## Development

Both release files are generated artifacts. Edit the modules under `src/`
(`_preamble.py` holds the docstring, version and imports; the rest follow the
Part numbering in `_make.py`), then regenerate before committing:

```bash
python _make.py        # rebuild vcd_analyzer.py + vcd_analyzer_lite.py
```

CI rejects any commit where a release file differs from a fresh assembly of
`src/`, and runs the full test suite on every push (Linux/macOS/Windows,
Python 3.9-3.13) — running it locally first is optional. Only `_preamble.py`
may contain module-level imports — the parts
share one namespace by concatenation, and `_make.py --check` enforces this.

The two variants are assembled from the same `src/` (only the Part-4 slot
differs: the lite build carries an explicit stub that errors clearly on
anything index-related) and can never diverge silently — `_make.py --check`
rejects a drifted release file, and CI enforces it.

## Tests

```bash
# Full pytest suite (requires pytest)
python -m pytest verify/ -v

# unittest only (stdlib, no extra installs)
python -m unittest discover -s verify -p "test_cli.py"
```

Covers helpers, parser internals, command functions, text/JSON modes, CLI
subprocess smoke, and three external real-world VCD samples.

## Agent skill

This repository includes a [skill/SKILL.md](skill/SKILL.md) for AI coding agents
(Codex, Claude Code, etc.). Install it directly from this repo and your agent
will know how to use all seven commands, pick the right one for each task,
parse JSON output, and follow proven debug workflows.

The skill covers the full command reference, decision tree, five workflow
patterns, condition syntax, error recovery, and environment variable tuning.

Per-release details live in [CHANGELOG.md](CHANGELOG.md) and on the
[GitHub Releases](https://github.com/neveltyc/VcdAnalyzer/releases) page.

## License

MIT &mdash; see [LICENSE](LICENSE). &copy; 2026 neveltyc

[中文说明](README_zh.md)
