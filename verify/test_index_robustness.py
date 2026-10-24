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
from conftest import run_cli
from test_index import _big_vcd

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
    sidecar = tmp_path / 'side.vcidx'
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


# ---- second-round review regressions --------------------------------------

def test_output_may_not_be_the_vcd_itself(tmp_path):
    """--output pointing at the input VCD must be refused BEFORE any build:
    publication would replace the waveform with the sidecar (P0). The VCD
    is named *.vcidx so the suffix guard passes and the identity guard is
    the one that fires."""
    import hashlib
    import shutil
    from conftest import run_cli
    src = tmp_path / 'waveform.vcidx'  # a VCD that ends with the suffix
    shutil.copy(_big_vcd(tmp_path), src)
    digest = hashlib.sha256(src.read_bytes()).hexdigest()
    result = run_cli(['index', str(src), '--output', str(src), '--force'])
    assert result.returncode != 0
    assert 'must not be the VCD file itself' in result.stderr
    assert hashlib.sha256(src.read_bytes()).hexdigest() == digest


def test_failed_rebuild_keeps_previous_sidecar(tmp_path, monkeypatch):
    """A failed rebuild must leave a pre-existing target untouched: builders
    clean their own temp files, never the published target (P1). The failure
    is injected in the CLI subprocess via VCD_ANALYZER_FAIL_INDEX (a test
    hook honored only when the env var is set)."""
    src = _big_vcd(tmp_path)
    sidecar = Path(va.sidecar_path(src))
    va.build_index(src, sidecar, 64)
    good = sidecar.read_bytes()
    monkeypatch.setenv('VCD_ANALYZER_FAIL_INDEX', '1')
    result = run_cli(['index', str(src), '--force'])
    assert result.returncode != 0
    assert sidecar.read_bytes() == good, 'failed rebuild destroyed the old sidecar'


def test_comment_body_never_becomes_split_anchor(tmp_path):
    """$comment bodies may legally contain '#<digits>' text; the parallel
    builder must not anchor a worker split there (section census gate)."""
    path = tmp_path / 'cmt.vcd'
    with open(path, 'w') as out:
        out.write('$timescale 1ps $end $scope module top $end '
                  '$var wire 1 ! a $end $upscope $end $enddefinitions $end\n')
        t = 0
        while path.stat().st_size < 1 << 20:
            out.write('#%d\n0!\n$comment rebuild at #%d pending $end\n1!\n' % (t, t + 1))
            t += 2
    env = dict(os.environ, VCD_ANALYZER_INDEX_THREADS='4',
               VCD_ANALYZER_INDEX_PARALLEL_MIN='1')
    import subprocess
    result = subprocess.run(
        [sys.executable, '-S', str(ROOT / 'vcd_analyzer.py'), '--json', 'index',
         str(path), '--output', str(tmp_path / 's.vcidx'), '--block-mib', '1'],
        capture_output=True, text=True, env=env, timeout=120)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['threads'] == 1  # census forced single
    idx = va.IndexedVCD(path, tmp_path / 's.vcidx', enforce_gate=False)
    raw = va.VCDParser(str(path))
    try:
        span = idx.blocks[-1][3]
        for frac in (10, 50, 90):
            a = span * frac // 100
            assert (list(raw.iter_transitions(a, a + max(1, span // 100), None))
                    == list(idx.iter_transitions(a, a + max(1, span // 100), None)))
    finally:
        idx.close()


def test_corrupt_directory_mode_detected_at_load(tmp_path):
    """Damage the DIRECTORY flags byte (not the file tail): try_index must
    reject at load time on a gate-passing file (P1, and the old test could
    not detect this at all)."""
    src = _big_vcd(tmp_path)
    va.build_index(src, va.sidecar_path(src), 64)
    assert va.try_index(src) is not None  # baseline: fresh and usable
    data = bytearray(Path(va.sidecar_path(src)).read_bytes())
    # directory entry for symbol 0: header(56) + blocks(32*nb) + 0*16 + 8 = mode
    nb = va.VCDParser(str(src)).scan_time_range()  # touch parser; nb via sidecar
    head = va.HEADER.unpack_from(bytes(data), 0)
    nb = head[4]
    off = 56 + 32 * nb + 8  # location(8) | count(4) | mode(4)
    data[off + 12] = 0x63  # 'c' — not a valid posting mode
    Path(va.sidecar_path(src)).write_bytes(bytes(data))
    va._warned.clear()
    assert va.try_index(src) is None


def test_output_requires_vcidx_suffix(tmp_path):
    """--output must produce a *.vcidx file: arbitrary extensions would
    leave unrecognizable binaries and invite confusion with the waveform."""
    from conftest import run_cli
    src = _big_vcd(tmp_path)
    bad = tmp_path / 'sidecar.bin'
    result = run_cli(['index', str(src), '--output', str(bad)])
    assert result.returncode != 0
    assert 'must end with .vcidx' in result.stderr
    assert not bad.exists()
    good = tmp_path / 'sidecar.vcidx'
    result = run_cli(['index', str(src), '--output', str(good)])
    assert result.returncode == 0, result.stderr
    assert good.exists()
