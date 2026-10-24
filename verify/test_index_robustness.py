"""Regression tests for the independent-review findings: malformed
timestamps under the multi-thread native builder (P0-1), truncated/
corrupt sidecars (P0-2), the stale-sidecar fd leak that blocked
auto-rebuild via lsof (P1-1), the malformed-#T bus-commit divergence
(P1-2), and --block-mib bounds (P2-4)."""
import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vcd_analyzer as va

ROOT = Path(__file__).resolve().parents[1]


def _malformed_ts_vcd(path, mib=70):
    """A >64 MiB file whose data section is littered with tolerated
    malformed '#1.5' timestamps — the review's P0-1 reproducer."""
    syms = b'!"#$%&\'()*+'
    chunk = (b'#0\n' + b''.join(b'%d%c\n' % (i % 2, c) for i, c in enumerate(syms))
             + b'#1.5\n1!\nb1010 #\n')
    with open(path, 'wb') as out:
        out.write(b'$timescale 1ps $end $scope module top $end\n')
        for i, c in enumerate(syms):
            out.write(b'$var wire 1 %c s%d $end\n' % (c, i))
        out.write(b'$var wire 4 # v $end\n$upscope $end\n$enddefinitions $end\n')
        t = 0
        while path.stat().st_size < mib << 20:
            out.write(chunk.replace(b'#0\n', b'#%d\n' % t))
            t += 3
    return path


@pytest.mark.skipif(not (ROOT / 'vcd_analyzer.py').exists(), reason='no release file')
def test_multithread_survives_malformed_timestamps(tmp_path):
    src = _malformed_ts_vcd(tmp_path / 'bad.vcd')
    env = dict(os.environ, VCD_ANALYZER_INDEX_THREADS='4',
               VCD_ANALYZER_INDEX_PARALLEL_MIN='1')
    sidecar = tmp_path / 'side.idx'
    result = subprocess.run(
        [sys.executable, '-S', str(ROOT / 'vcd_analyzer.py'), '--json', 'index',
         str(src), '--output', str(sidecar), '--block-mib', '1'],
        capture_output=True, text=True, env=env, timeout=300)
    assert result.returncode == 0, result.stderr
    idx = va.IndexedVCD(src, sidecar, enforce_gate=False)
    raw = va.VCDParser(str(src))
    try:
        # block times must stay monotonic: readers bisect them
        ends = [b[3] for b in idx.blocks]
        assert ends == sorted(ends)
        assert 0 not in ends[1:], 'zero-time block after the first (P0-1)'
        span = ends[-1]
        for frac in (5, 25, 50, 75, 95):
            a = span * frac // 100
            b = a + max(1, span // 50)
            assert (list(raw.iter_transitions(a, b, None))
                    == list(idx.iter_transitions(a, b, None))), (frac, 'window')
    finally:
        idx.close()


def test_truncated_sidecar_falls_back_cleanly(tmp_path, capsys):
    src = tmp_path / 'x.vcd'
    src.write_text('$timescale 1ns $end $scope module top $end $var wire 1 ! a $end '
                   '$upscope $end $enddefinitions $end #0 0! #5 1!')
    for size in (0, 10, 55, 60):
        with open(va.sidecar_path(src), 'wb') as f:
            f.write(b'\x00' * size)
        va._warned.clear()
        wrapped = va.try_index(src)  # must never raise (P0-2)
        assert wrapped is None, size
        captured = capsys.readouterr()
        assert 'ignoring' in captured.err, size


def test_stale_sidecar_does_not_leak_fd(tmp_path):
    import shutil
    from test_index import _big_vcd
    src = _big_vcd(tmp_path)
    va.build_index(src, va.sidecar_path(src), 64)
    os.utime(src)  # stale: source newer than the recorded mtime
    def count_fds():
        return len(os.listdir('/dev/fd')) if os.path.exists('/dev/fd') else None
    if count_fds() is None:
        pytest.skip('no /dev/fd')
    before = count_fds()
    for _ in range(5):
        assert va.try_index(src) is None
    assert count_fds() == before, 'stale sidecar leaked fds (P1-1)'


def test_malformed_timestamp_is_not_a_bus_commit(tmp_path):
    """'#1.5' between bit writes must not flush the bus early: the
    reference parser skips malformed timestamps entirely (P1-2)."""
    path = tmp_path / 'bus.vcd'
    path.write_text(
        '$timescale 1ns $end $scope module top $end '
        '$var wire 1 ! b [0] $end $var wire 1 " b [1] $end '
        '$upscope $end $enddefinitions $end '
        '#0 0! 0" #10 1! #1.5 1" #20 0! 1"')
    va.build_index(path, tmp_path / 'bus.idx', 4096)
    idx = va.IndexedVCD(path, tmp_path / 'bus.idx', enforce_gate=False)
    raw = va.VCDParser(str(path))
    try:
        assert list(raw.iter_transitions(0, 30, None)) == \
               list(idx.iter_transitions(0, 30, None))
        # and specifically at the malformed tick: state must be the
        # pre-malformed assembled value, not a cross-bit intermediate
        assert idx.state_at(12) == raw.state_at(12)
    finally:
        idx.close()


@pytest.mark.parametrize('mib', [0, -1, 5000])
def test_block_mib_bounds(tmp_path, mib):
    from conftest import run_cli
    src = tmp_path / 'x.vcd'
    src.write_text('$scope module top $end $var wire 1 ! a $end $upscope $end '
                   '$enddefinitions $end #0 0!')
    result = run_cli(['index', str(src), '--block-mib', str(mib)])
    assert result.returncode != 0
    assert '--block-mib' in result.stderr
