"""Variant tests: vcd_analyzer.py (full, index + native) vs
vcd_analyzer_lite.py (pure Python, 1.5.6 behavior, no index). The two
never diverge silently: everything index-related answers clearly in lite,
and full never nags when its native builder is doing the work."""
import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vcd_analyzer as va

ROOT = Path(__file__).resolve().parents[1]
FULL = ROOT / 'vcd_analyzer.py'
LITE = ROOT / 'vcd_analyzer_lite.py'


def _run(script, args, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run([sys.executable, '-S', str(script)] + list(map(str, args)),
                          capture_output=True, text=True, env=env, timeout=120)


def _big_file(tmp_path, mib=66):
    """A gate-passing VCD large enough (>= 64 MiB) to trigger the notice."""
    path = tmp_path / 'big.vcd'
    chunk = b'#0\n1!\n0!\nb1 #\nb0 #\n' * 4096
    with open(path, 'wb') as out:
        out.write(b'$timescale 1ns $end $scope module top $end '
                  b'$var wire 1 ! a $end $var wire 4 # v $end $upscope $end '
                  b'$enddefinitions $end\n')
        while path.stat().st_size < mib << 20:
            out.write(chunk)
    old = os.stat(path).st_mtime - 3600
    os.utime(path, (old, old))
    return path


def test_lite_index_errors_with_full_pointer(tmp_path):
    src = _big_file(tmp_path, mib=1)  # size irrelevant: the gate is the command
    result = _run(LITE, ['index', str(src)])
    assert result.returncode != 0
    assert 'full vcd_analyzer.py only' in result.stderr
    assert not os.path.exists(va.sidecar_path(src))


def test_lite_index_pointer_for_every_invocation(tmp_path):
    """--force, an existing sidecar and the hidden --auto all get the same
    pointer — never a traceback or a full-build-only message."""
    src = _big_file(tmp_path, mib=1)
    open(va.sidecar_path(src), 'wb').close()
    for extra in ([], ['--force'], ['--auto']):
        result = _run(LITE, ['index', str(src)] + extra)
        assert result.returncode == 1, extra
        assert 'full vcd_analyzer.py only' in result.stderr, extra
        assert 'Traceback' not in result.stderr, extra


def test_lite_env_options_notice(tmp_path):
    src = _big_file(tmp_path, mib=1)
    result = _run(LITE, ['info', str(src)],
                  {'VCD_ANALYZER_AUTO_INDEX': '1',
                   'VCD_ANALYZER_INDEX_THREADS': '4'})
    assert result.returncode == 0, result.stderr
    assert 'full-version option and is ignored' in result.stderr
    assert 'VCD_ANALYZER_AUTO_INDEX' in result.stderr
    assert 'VCD_ANALYZER_INDEX_THREADS' in result.stderr


def test_lite_queries_unaffected(tmp_path):
    # lite is the 1.5.6 program: no sidecar is read even if one exists.
    src = _big_file(tmp_path, mib=1)
    result = _run(FULL, ['index', str(src)])
    assert result.returncode == 0, result.stderr
    assert os.path.exists(va.sidecar_path(src))
    lite = _run(LITE, ['--json', 'snapshot', str(src), '--at', '1'])
    full = _run(FULL, ['--json', 'snapshot', str(src), '--at', '1'])
    assert lite.returncode == 0 and full.returncode == 0
    assert json.loads(lite.stdout) == json.loads(full.stdout)


def test_full_python_fallback_advises_on_big_files(tmp_path, monkeypatch):
    """When the embedded native builder cannot serve a platform, the
    pure-Python fallback runs and says so on files big enough to care."""
    src = _big_file(tmp_path, mib=1)
    monkeypatch.setattr(va, 'native_index_build', lambda *a, **k: None)
    monkeypatch.setattr(va, '_SLOW_BUILD_NOTE_BYTES', 1 << 20)
    out = io.StringIO()
    options = argparse.Namespace(file=str(src), block_mib=8, force=True,
                                 output=None, auto=False, json=False,
                                 limit=None, verbose=False)
    with contextlib.redirect_stdout(out):
        va.cmd_index(va.VCDParser(str(src)), options)
    assert 'no native builder for this platform' in out.getvalue()


def test_full_native_does_not_nag(tmp_path):
    src = _big_file(tmp_path)
    result = _run(FULL, ['index', str(src)])
    assert result.returncode == 0, result.stderr
    assert 'no native builder' not in result.stdout
    assert 'VCD_ANALYZER_INDEX_THREADS is ignored' not in result.stderr
