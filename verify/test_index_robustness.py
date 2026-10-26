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
    """A >64 MiB file (the native builder only splits work into chunks of
    at least 16 MiB) whose data section is littered with tolerated
    malformed '#1.5' timestamps, which the multi-thread builder once turned
    into zero-time blocks."""
    syms = b'!"#$%&\'()*+'
    body = (b''.join(b'%d%c\n' % (i % 2, c) for i, c in enumerate(syms))
            + b'#1.5\n1!\nb1010 #\n')
    per_chunk = len(body) + 8
    count = (mib << 20) // per_chunk + 1
    with open(path, 'wb') as out:
        out.write(b'$timescale 1ps $end $scope module top $end\n')
        for i, c in enumerate(syms):
            out.write(b'$var wire 1 %c s%d $end\n' % (c, i))
        out.write(b'$var wire 4 # v $end\n$upscope $end\n$enddefinitions $end\n')
        out.write(b''.join(b'#%d\n' % (3 * k) + body for k in range(count)))
    return path


def _single_thread_reference(src, sidecar, monkeypatch, block_mib):
    """A single-threaded native index of src: the reference the multi-thread
    builds are compared with across the whole file. (The single-threaded
    builder is proven equal to the plain parser by test_index_equivalence;
    a plain-parser reference this deep into a 70 MiB file costs tens of
    seconds per window, so the plain parser checks the first window only.)"""
    monkeypatch.setenv('VCD_ANALYZER_INDEX_THREADS', '1')
    stats = va.native_index_build(str(src), str(sidecar), block_mib << 20)
    monkeypatch.delenv('VCD_ANALYZER_INDEX_THREADS')
    if stats is None:
        pytest.skip('no native builder on this platform')
    assert stats['threads'] == 1
    return va.IndexedVCD(src, sidecar, enforce_gate=False)


def _windows_agree(idx, ref, raw, fracs):
    """idx answers like the plain parser in the first window and like the
    single-threaded reference in every window (narrow windows: one block)."""
    span = idx.blocks[-1][3]
    for k, frac in enumerate(fracs):
        a = span * frac // 100
        b = a + max(1, span // 2000)
        got = list(idx.iter_transitions(a, b, None))
        assert got, (frac, 'empty window')
        assert got == list(ref.iter_transitions(a, b, None)), (frac, 'window')
        if k == 0:
            assert got == list(raw.iter_transitions(a, b, None)), (frac, 'raw')


@pytest.mark.skipif(not (ROOT / 'vcd_analyzer.py').exists(), reason='no release file')
def test_multithread_survives_malformed_timestamps(tmp_path, monkeypatch):
    src = _malformed_ts_vcd(tmp_path / 'bad.vcd')
    env = dict(os.environ, VCD_ANALYZER_INDEX_THREADS='4',
               VCD_ANALYZER_INDEX_PARALLEL_MIN='1')
    sidecar = tmp_path / 'side.vcidx'
    result = subprocess.run(
        [sys.executable, '-S', str(ROOT / 'vcd_analyzer.py'), '--json', 'index',
         str(src), '--output', str(sidecar), '--block-mib', '1'],
        capture_output=True, text=True, env=env, timeout=300)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['threads'] == 4
    idx = va.IndexedVCD(src, sidecar, enforce_gate=False)
    ref = _single_thread_reference(src, tmp_path / 'ref.vcidx', monkeypatch, 1)
    raw = va.VCDParser(str(src))
    try:
        # block times must stay monotonic: readers bisect them
        ends = [b[3] for b in idx.blocks]
        assert ends == sorted(ends)
        assert 0 not in ends[1:], 'zero-time block after the first'
        _windows_agree(idx, ref, raw, (5, 25, 50, 75, 95))
    finally:
        idx.close()
        ref.close()


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


def test_fingerprint_catches_same_size_same_mtime_rewrite(tmp_path, capsys):
    """A different dump with the same size and a preserved mtime (cp -p,
    rsync -t, tar) passes the (size, mtime_ns) header check; the content
    fingerprint footer must still reject the sidecar."""
    src = _big_vcd(tmp_path)
    va.build_index(src, va.sidecar_path(src), 64)
    idx = va.try_index(src)
    assert idx is not None
    idx.close()
    stat = os.stat(src)
    data = bytearray(src.read_bytes())
    tail = data.rindex(b'#')
    data[tail + 1:tail + 2] = b'9' if data[tail + 1:tail + 2] != b'9' else b'8'
    src.write_bytes(bytes(data))
    os.utime(src, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    assert os.stat(src).st_size == stat.st_size
    va._warned.clear()
    assert va.try_index(src) is None
    assert 'source content changed' in capsys.readouterr().err
    assert not va._sidecar_fresh(src, va.sidecar_path(src))


def test_sidecar_without_fingerprint_is_rebuilt(tmp_path, capsys):
    """A 1.6.0 sidecar (no footer) counts as stale, never as fresh."""
    src = _big_vcd(tmp_path)
    sidecar = va.sidecar_path(src)
    va.build_index(src, sidecar, 64)
    with open(sidecar, 'r+b') as f:
        f.truncate(os.path.getsize(sidecar) - va.FOOTER.size)
    va._warned.clear()
    assert va.try_index(src) is None
    assert 'ignoring' in capsys.readouterr().err
    assert not va._sidecar_fresh(src, sidecar)


def test_native_build_carries_fingerprint(tmp_path):
    src = _big_vcd(tmp_path)
    sidecar = va.sidecar_path(src)
    stats = va.native_index_build(str(src), sidecar, 1 << 20)
    if stats is None:
        pytest.skip('no native builder on this platform')
    assert stats['index_bytes'] == os.path.getsize(sidecar)
    assert va._sidecar_fresh(src, sidecar)
    assert [p.name for p in tmp_path.iterdir() if '.native.' in p.name] == []


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


# ---- fourth-round review regressions ---------------------------------------

def _bus_and_scalars(path):
    """64 scalars + one 8-bit exploded bus; the bus writes ONLY in the
    first ~2%, the scalars write throughout."""
    bits = ['!', '"', '#', '$', '%', '&', "'", '(']
    syms = [chr(40 + i) for i in range(64)]  # ')','*',...
    with open(path, 'w') as out:
        out.write('$timescale 1ps $end $scope module top $end\n')
        for i, s in enumerate(syms):
            out.write('$var wire 1 {} sc{} $end\n'.format(s, i))
        for i, s in enumerate(bits):
            out.write('$var wire 1 {} bus [{}] $end\n'.format(s, i))
        out.write('$upscope $end\n$enddefinitions $end\n')
        t = 0
        while path.stat().st_size < 8 << 20:
            chunk = ['#%d\n' % t]
            for i, s in enumerate(syms):
                chunk.append('%d%s\n' % (t // 5 % 2, s))
            if t < 200000:  # bus writes only near the start
                for i, s in enumerate(bits):
                    chunk.append('%d%s\n' % (t // 7 % 2, s))
            out.write(''.join(chunk))
            t += 2
    return syms, bits


def test_scalar_query_not_widened_by_unrelated_buses(tmp_path):
    """A scalar-only selection must keep hit-block random access even when
    the file contains exploded buses (include_range was once keyed on the
    FILE having buses, not the QUERY selecting one)."""
    path = tmp_path / 'bus.vcd'
    syms, _bits = _bus_and_scalars(path)
    # either builder: the property under test is the query's block reads
    va.build_index_best(str(path), str(tmp_path / 'b.vcidx'), 1 << 20)
    raw = va.VCDParser(str(path))
    scalar_sid = next(s for s in raw.signals if raw.signals[s]['path'].endswith('sc63'))
    idx = va.IndexedVCD(path, tmp_path / 'b.vcidx', enforce_gate=False)
    try:
        # window far from any bus write; scalar-only selection
        span = idx.blocks[-1][3]
        a, b = span * 80 // 100, span * 85 // 100
        exp = list(raw.iter_transitions(a, b, {scalar_sid}))
        act = list(idx.iter_transitions(a, b, {scalar_sid}))
        assert exp == act
        assert idx.counters['blocks'] <= 3, (
            'scalar query read {} blocks — bus widening still active'.format(
                idx.counters['blocks']))
    finally:
        idx.close()


def _toggles(t, nbytes):
    """'#t 0! 1!' records from time t on, about nbytes of text."""
    out = []
    size = 0
    while size < nbytes:
        record = '#%d\n0!\n1!\n' % t
        out.append(record)
        size += len(record)
        t += 2
    return ''.join(out)


def test_native_contained_comment_keeps_parallel(tmp_path, monkeypatch):
    """A $comment fully inside one worker's range must NOT trigger the
    single-threaded fallback (parallel_fallback False, threads 4)."""
    path = tmp_path / 'cmt.vcd'
    filler = 'lorem ipsum dolor sit amet ' * 2000
    with open(path, 'w') as out:
        out.write('$timescale 1ps $end $scope module top $end '
                  '$var wire 1 ! a $end $upscope $end $enddefinitions $end\n')
        out.write('#0\n1!\n')
        out.write('$comment %s $end\n' % filler)  # ~52 KB, well before 25%
        out.write(_toggles(2, 70 << 20))
    env = dict(os.environ, VCD_ANALYZER_INDEX_THREADS='4',
               VCD_ANALYZER_INDEX_PARALLEL_MIN='1')
    result = subprocess.run(
        [sys.executable, '-S', str(ROOT / 'vcd_analyzer.py'), '--json', 'index',
         str(path), '--output', str(tmp_path / 'c.vcidx'), '--block-mib', '1'],
        capture_output=True, text=True, env=env, timeout=300)
    assert result.returncode == 0, result.stderr
    stats = json.loads(result.stdout)
    assert stats['threads'] == 4
    assert stats['parallel_fallback'] is False
    idx = va.IndexedVCD(path, tmp_path / 'c.vcidx', enforce_gate=False)
    ref = _single_thread_reference(path, tmp_path / 'ref.vcidx', monkeypatch, 1)
    raw = va.VCDParser(str(path))
    try:
        _windows_agree(idx, ref, raw, (10, 50, 90))
    finally:
        idx.close()
        ref.close()


def test_native_straddling_comment_falls_back(tmp_path, monkeypatch):
    """A $comment body SPANNING the midpoint split (2 MB of text starting
    just before size/2, containing a '#123456' token so the anchor lands
    inside it) must fall back to the single-threaded parse — and the
    result must still equal the plain parser."""
    path = tmp_path / 'straddle.vcd'
    half_filler = 'rebuild pending #987654 todo ' * 70000  # ~2 MB
    # 34 MiB of toggles, the comment, then 34 MiB more: the comment body
    # spans the file midpoint (the split anchor is the first '#digits'
    # at/after size/2, which then lands INSIDE the comment body). Worker
    # chunks are at least 16 MiB, so the file must stay this large.
    first = _toggles(2, 34 << 20)
    t = 2 + 2 * first.count('#')
    with open(path, 'w') as out:
        out.write('$timescale 1ps $end $scope module top $end '
                  '$var wire 1 ! a $end $upscope $end $enddefinitions $end\n')
        out.write('#0\n1!\n')
        out.write(first)
        out.write('$comment %s $end\n' % half_filler)
        out.write(_toggles(t, 34 << 20))
    env = dict(os.environ, VCD_ANALYZER_INDEX_THREADS='4',
               VCD_ANALYZER_INDEX_PARALLEL_MIN='1')
    result = subprocess.run(
        [sys.executable, '-S', str(ROOT / 'vcd_analyzer.py'), '--json', 'index',
         str(path), '--output', str(tmp_path / 's.vcidx'), '--block-mib', '1'],
        capture_output=True, text=True, env=env, timeout=300)
    assert result.returncode == 0, result.stderr
    stats = json.loads(result.stdout)
    assert stats['parallel_fallback'] is True
    idx = va.IndexedVCD(path, tmp_path / 's.vcidx', enforce_gate=False)
    ref = _single_thread_reference(path, tmp_path / 'ref.vcidx', monkeypatch, 1)
    raw = va.VCDParser(str(path))
    try:
        _windows_agree(idx, ref, raw, (10, 50, 90))
        span = idx.blocks[-1][3]
        assert idx.state_at(span // 2) == ref.state_at(span // 2)
    finally:
        idx.close()
        ref.close()
