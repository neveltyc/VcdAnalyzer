"""End-to-end tests for the full variant's embedded native index builder
(vcd_analyzer.py carries the native part; vcd_analyzer_lite.py has none).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vcd_analyzer as va

ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / 'vcd_analyzer.py'
FIXTURES = sorted((Path(__file__).parent / 'fixtures').glob('*.vcd')) + \
           sorted((Path(__file__).parent / 'samples').glob('*.vcd'))


def run_fast(args, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run([sys.executable, str(FULL)] + args,
                          capture_output=True, text=True, env=env)


def test_fast_reports_native_builder(tmp_path):
    src = tmp_path / 'copy.vcd'
    src.write_bytes(FIXTURES[0].read_bytes())
    result = run_fast(['--json', 'index', str(src)])
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['builder'] == 'native'
    # Tiny fixtures legitimately fail the usage gate; what matters is that
    # the native sidecar exists and loads (enforce_gate bypasses the gate).
    assert os.path.exists(va.sidecar_path(src))
    idx = va.IndexedVCD(src, va.sidecar_path(src), enforce_gate=False)
    idx.close()


def test_fast_native_sidecar_matches_python(tmp_path):
    """The embedded native builder must produce a sidecar whose query
    answers equal both the pure-Python sidecar and the plain parser."""
    checks = 0
    for fx in FIXTURES:
        src = tmp_path / fx.name
        src.write_bytes(fx.read_bytes())
        assert run_fast(['--json', 'index', str(src)]).returncode == 0
        va.build_index(src, tmp_path / 'py.idx', 8 << 20)
        raw = va.VCDParser(str(src))
        a = va.IndexedVCD(src, va.sidecar_path(src), enforce_gate=False)
        b = va.IndexedVCD(src, tmp_path / 'py.idx', enforce_gate=False)
        try:
            times = sorted({t for t, _s, _v in raw.iter_events()} | {0, 10, 20})
            selections = [None] + ([{sorted(raw.signals)[0]}] if raw.signals else [])
            for selected in selections:
                for t in times:
                    assert a.state_at(t, selected) == b.state_at(t, selected), (fx.name, t)
                    checks += 1
                assert list(a.iter_transitions(0, None, selected)) == \
                       list(b.iter_transitions(0, None, selected)), fx.name
                checks += 1
        finally:
            a.close()
            b.close()
    assert checks > 100


def test_fast_unsupported_platform_falls_back(monkeypatch):
    """No knob: a platform without an embedded library silently uses the
    pure-Python builder (the only supported way to reach it)."""
    monkeypatch.setattr(va, '_native_platform_key', lambda: None)
    assert va._NATIVE_INDEX_BUILD('whatever', 'whatever.idx', 8) is None
    assert va.native_index_build('whatever', 'whatever.idx', 8) is None
    # and automatic building is off by default there (it would only run
    # the slow pure-Python pass): one notice, no background spawn
    va._warned.clear()
    import argparse as _ap
    opts = _ap.Namespace(file='whatever')
    assert va.maybe_auto_build(va.VCDParser.__new__(va.VCDParser), 'whatever') is None


def test_fast_non_monotonic_clean_error(tmp_path):
    src = tmp_path / 'bad.vcd'
    src.write_text('$scope module top $end $var wire 1 ! a $end $upscope $end '
                   '$enddefinitions $end #10 0! #5 1!')
    result = run_fast(['index', str(src)])
    assert result.returncode != 0
    assert 'non-monotonic' in result.stderr
