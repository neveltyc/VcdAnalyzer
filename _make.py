#!/usr/bin/env python3
"""Assemble src/ into the single-file vcd_analyzer.py for release.

Usage:
    python _make.py          # build vcd_analyzer.py
    python _make.py --check  # verify vcd_analyzer.py matches src/

The module order matches the Part numbering in the assembled file:

    _preamble.py    shebang, docstring, imports, version
    timebase.py     Part 1:  time units, exact tick math, resource limits,
                             shared 4-state/real/port tables, exceptions
    values.py       Part 2:  value formatting, clamping, filter patterns
    parser.py       Part 3:  VCDParser (header, bit-exploded reassembly,
                             change stream)  (syncs with OpenWaveAnalyzer)
    output.py       Part 4:  JSON/text output helpers, limits, truncation
    conditions.py   Part 5:  search condition parse/resolve/evaluate and
                             per-timestamp stream grouping
    summary.py      Part 6:  window summary rows
    commands.py     Part 7:  the seven commands
    cli.py          Part 8:  argparse wiring and entry point

Each file is concatenated as-is, so the assembled output is a byte-level
exact reproduction of the modules — `--check` (run in CI) fails the build
whenever vcd_analyzer.py drifts from src/.

Maintenance rule (enforced by CI): edit src/, never the release file, then

    python _make.py && python -m pytest verify/ -q && python _make.py --check

Discipline: only _preamble.py may contain module-level imports — the parts
share one namespace by concatenation, and a stray import would still work
but hides dependencies; --check rejects it. A planned `--fast` variant
(standard file + embedded compressed native index-builder libraries for
arm64-linux / x86-64-linux / arm64-macos / x86-64-windows via ctypes)
will append a loader part; it is not assembled yet.
"""

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC_DIR = HERE / 'src'
OUTPUT = HERE / 'vcd_analyzer.py'

# Assembly order — must match the Part sequence.
MODULE_ORDER = [
    '_preamble.py',
    'timebase.py',
    'values.py',
    'parser.py',
    'output.py',
    'conditions.py',
    'summary.py',
    'commands.py',
    'cli.py',
]

_TOP_LEVEL_IMPORT = re.compile(r'^(?:import|from)\s', re.MULTILINE)


def check_discipline(text_by_module):
    """Only _preamble.py may import at module level (column-0 import/from)."""
    problems = []
    for name in MODULE_ORDER:
        if name == '_preamble.py':
            continue
        match = _TOP_LEVEL_IMPORT.search(text_by_module[name])
        if match:
            line = text_by_module[name][:match.start()].count('\n') + 1
            problems.append(f'{name}:{line}: module-level import outside _preamble.py')
    return problems


def assemble() -> str:
    parts = {}
    for name in MODULE_ORDER:
        path = SRC_DIR / name
        if not path.exists():
            sys.exit(f'Error: missing module {path}')
        parts[name] = path.read_text(encoding='utf-8')
    problems = check_discipline(parts)
    if problems:
        for p in problems:
            print(f'Error: {p}', file=sys.stderr)
        sys.exit(1)
    return ''.join(parts[name] for name in MODULE_ORDER)


def main():
    check_mode = '--check' in sys.argv

    assembled = assemble()

    if check_mode:
        if not OUTPUT.exists():
            sys.exit(f'Error: {OUTPUT} does not exist; run without --check first')
        current = OUTPUT.read_text(encoding='utf-8')
        # Normalize line endings for comparison
        current_norm = current.replace('\r\n', '\n')
        assembled_norm = assembled.replace('\r\n', '\n')
        if current_norm == assembled_norm:
            print(f'OK: {OUTPUT.name} matches src/')
            return
        cur_lines = current_norm.splitlines()
        asm_lines = assembled_norm.splitlines()
        shown = 0
        for i, (a, b) in enumerate(zip(cur_lines, asm_lines)):
            if a != b:
                print(f'MISMATCH at line {i+1}:')
                print(f'  release: {a[:120]}')
                print(f'  src:     {b[:120]}')
                shown += 1
                if shown >= 3:
                    break
        if not shown:
            diff = len(cur_lines) - len(asm_lines)
            print(f'MISMATCH: line count differs by {diff} '
                  f'(release={len(cur_lines)}, src={len(asm_lines)}); '
                  f'rerun: python _make.py')
        sys.exit(1)

    OUTPUT.write_text(assembled, encoding='utf-8', newline='\n')
    line_count = assembled.count('\n')
    size_kb = len(assembled.encode()) / 1024
    print(f'Assembled {OUTPUT.name}: {line_count} lines, '
          f'{size_kb:.0f} KB from {len(MODULE_ORDER)} modules')


if __name__ == '__main__':
    main()
