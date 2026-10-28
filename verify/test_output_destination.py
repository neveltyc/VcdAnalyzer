"""Where results go: --output FILE, the terminal budget, and the decimal
rendering of wide vectors (identical on every Python and environment)."""
import contextlib
import decimal
import io
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vcd_analyzer as va
from conftest import run_cli, write_vcd, minimal_vcd

FIXTURE = Path(__file__).parent / 'fixtures' / 'basic_trace.vcd'


# ---- decimal rendering -----------------------------------------------------

def _exact_decimal(n):
    ctx = decimal.Context(prec=decimal.MAX_PREC, Emax=decimal.MAX_EMAX)
    return str(ctx.create_decimal(n))


@pytest.mark.parametrize('width', [8, 64, 2048, 2049, 14285, 16384, 65536])
def test_wide_vectors_always_render_decimal_and_hex(width):
    """The format depends on nothing but the value: str(int) refusing more
    than sys.get_int_max_str_digits() digits once made wide values fall
    back to binary, on some Python patch levels and environments only."""
    if hasattr(sys, 'set_int_max_str_digits'):
        old = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(640)  # the smallest limit a user can set
    try:
        value = '1' * width
        n = (1 << width) - 1
        text = va.fmt_val(value, {'width': width})
        top = '137'[width % 4 - 1] if width % 4 else ''
        assert text == '{} (0x{})'.format(_exact_decimal(n), top + 'f' * (width // 4))
    finally:
        if hasattr(sys, 'set_int_max_str_digits'):
            sys.set_int_max_str_digits(old)


def test_small_values_of_wide_vectors_unchanged():
    assert va.fmt_val('101', {'width': 16384}) == '5 (0x{})'.format('0' * 4095 + '5')
    assert va.fmt_val('1x', {'width': 4}) == 'b001x'


# ---- --output FILE ----------------------------------------------------------

@pytest.mark.parametrize('command', [
    ['dump'], ['--json', 'dump'], ['summary'], ['snapshot', '--at', '10ns'],
    ['--limit', '0', 'dump'], ['list'], ['info']])
def test_output_file_holds_exactly_the_stdout_result(tmp_path, command):
    plain = run_cli(_with_file(command, FIXTURE))
    assert plain.returncode == 0, plain.stderr
    target = tmp_path / 'result.out'
    saved = run_cli(_with_file(command, FIXTURE) + ['--output', str(target)])
    assert saved.returncode == 0, saved.stderr
    assert target.read_text(encoding='utf-8') == plain.stdout
    lines = plain.stdout.count('\n')
    if '--json' in command:
        receipt = json.loads(saved.stdout)
        assert receipt == {'output': str(target), 'bytes': target.stat().st_size,
                           'lines': lines}
    else:
        assert saved.stdout == 'Wrote {:,} lines ({:,} bytes) to {}\n'.format(
            lines, target.stat().st_size, target)
    assert [p.name for p in tmp_path.iterdir()] == ['result.out']


def _with_file(command, path):
    """Insert the VCD path right after the subcommand."""
    for i, word in enumerate(command):
        if word in ('dump', 'summary', 'snapshot', 'list', 'info', 'search', 'compare'):
            return command[:i + 1] + [str(path)] + command[i + 1:]
    raise AssertionError(command)


def test_output_errors_leave_nothing_behind(tmp_path):
    target = tmp_path / 'r.txt'
    bad = run_cli(['search', str(FIXTURE), '--condition', 'nosuchsignal=1', '-o', str(target)])
    assert bad.returncode != 0
    assert list(tmp_path.iterdir()) == []
    missing = run_cli(['dump', str(FIXTURE), '-o', str(tmp_path / 'no' / 'r.txt')])
    assert missing.returncode != 0 and 'cannot write --output' in missing.stderr
    src = tmp_path / 'copy.vcd'
    src.write_bytes(FIXTURE.read_bytes())
    same = run_cli(['dump', str(src), '-o', str(src)])
    assert same.returncode != 0 and 'must not be the VCD file itself' in same.stderr
    assert src.read_bytes() == FIXTURE.read_bytes()


# ---- terminal budget --------------------------------------------------------

class _FakeTerminal(io.StringIO):
    def isatty(self):
        return True


def _flood(lines):
    def command(_vcd, _args):
        for i in range(lines):
            print('line {:08d} {}'.format(i, 'x' * 60))
    return command


def test_terminal_output_stops_after_budget(monkeypatch):
    terminal = _FakeTerminal()
    errors = io.StringIO()
    monkeypatch.setattr(sys, 'stdout', terminal)
    monkeypatch.setattr(sys, 'stderr', errors)
    va._run_command(_flood(40000), None, argparse_ns())  # ~2.9 MB of text
    shown = terminal.getvalue()
    assert va._TERMINAL_BUDGET - 100 < len(shown) <= va._TERMINAL_BUDGET
    assert shown.endswith('\n') and shown.splitlines()[-1].startswith('line ')
    assert 'OUTPUT CUT' in errors.getvalue() and '--output FILE' in errors.getvalue()
    assert sys.stdout is terminal


def test_pipes_and_small_results_are_untouched(monkeypatch):
    pipe = io.StringIO()  # isatty() is False
    monkeypatch.setattr(sys, 'stdout', pipe)
    va._run_command(_flood(40000), None, argparse_ns())
    assert pipe.getvalue().count('\n') == 40000
    terminal = _FakeTerminal()
    errors = io.StringIO()
    monkeypatch.setattr(sys, 'stdout', terminal)
    monkeypatch.setattr(sys, 'stderr', errors)
    va._run_command(_flood(100), None, argparse_ns())
    assert terminal.getvalue().count('\n') == 100 and errors.getvalue() == ''


def argparse_ns():
    import argparse
    return argparse.Namespace(output_file=None, file=str(FIXTURE), json=False)
