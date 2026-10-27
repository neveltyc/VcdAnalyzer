"""Tests for index-building ergonomics: --output + symlink fallback, the
background auto-build (single-flight lock, kill switch, stale rebuild,
writer-hold detection). POSIX-only: symlink, chmod and lock semantics."""
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vcd_analyzer as va

from test_index import _big_vcd  # gate-passing synthetic file helper

pytestmark = pytest.mark.skipif(sys.platform == 'win32',
                                reason='POSIX symlink/chmod/lock semantics')


def _clear_autobuild_state():
    va._warned.clear()


def _settled(path):
    """Backdate mtime: a fresh file looks like a live writer and the
    auto-build correctly refuses to touch it."""
    old = time.time() - 3600
    os.utime(path, (old, old))


def test_output_with_symlink(tmp_path):
    src = _big_vcd(tmp_path)
    _settled(src)
    out = tmp_path / 'cust' / 'sidecar.vcidx'
    out.parent.mkdir()
    result = _run_cli(['index', str(src), '--output', str(out)])
    assert result.returncode == 0, result.stderr
    assert out.exists()
    link = Path(va.sidecar_path(src))
    assert link.is_symlink() and os.path.realpath(link) == str(out)
    # queries auto-use the linked sidecar
    snap = _run_cli(['--json', 'snapshot', str(src), '--at', '1'])
    assert snap.returncode == 0, snap.stderr


@pytest.mark.skipif(hasattr(os, 'geteuid') and os.geteuid() == 0,
                    reason='root ignores the read-only directory permission')
def test_output_link_failure_warns(tmp_path):
    # A read-only vcd directory makes the symlink fail for real; the build
    # itself still succeeds at --output and the failure is reported.
    vcd_dir = tmp_path / 'vcds'
    vcd_dir.mkdir()
    src = _big_vcd(vcd_dir)
    _settled(src)
    out = tmp_path / 'elsewhere.vcidx'
    os.chmod(vcd_dir, 0o500)  # sidecar link cannot land next to the vcd
    try:
        _clear_autobuild_state()
        result = _run_cli(['index', str(src), '--output', str(out)])
        assert result.returncode == 0, result.stderr
        assert out.exists()
        assert 'link failed' in result.stderr
    finally:
        os.chmod(vcd_dir, 0o700)


def _run_cli_any_size(args):
    """Run the CLI with the automatic-build size floor lifted, so the small
    synthetic files here exercise the same path a 50 MiB dump takes."""
    import subprocess
    from conftest import SCRIPT
    code = ('import sys; sys.argv = sys.argv[1:]; sys.path.insert(0, {!r}); '
            'import vcd_analyzer as va; va._AUTO_INDEX_MIN_BYTES = 0; va.main()'
            ).format(str(SCRIPT.parent))
    return subprocess.run([sys.executable, '-S', '-c', code, str(SCRIPT)]
                          + list(map(str, args)), text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)


def test_auto_build_spawn(tmp_path):
    _clear_autobuild_state()
    src = _big_vcd(tmp_path)
    _settled(src)
    snap = _run_cli_any_size(['--json', 'snapshot', str(src), '--at', '1'])
    assert snap.returncode == 0, snap.stderr
    assert 'building index in the background' in snap.stderr
    sidecar = Path(va.sidecar_path(src))
    for _ in range(100):  # background build of a ~200 KiB file is instant
        if sidecar.exists() and va._sidecar_fresh(src, str(sidecar)):
            break
        time.sleep(0.1)
    assert sidecar.exists(), 'background build never produced the sidecar'
    # once the builder finishes, the OS lock is released: we can take it
    fd = None
    for _ in range(100):
        fd = va._acquire_build_lock(str(sidecar))
        if fd is not None:
            break
        time.sleep(0.1)
    assert fd is not None, 'builder never released the lock'
    os.close(fd)
    # a successful background build leaves no log behind
    assert not os.path.exists(str(sidecar) + '.log')


def test_auto_build_below_floor_leaves_no_files(tmp_path):
    """A gate-passing file below _AUTO_INDEX_MIN_BYTES is answered by the
    plain parser and nothing is written next to it — not even a lock."""
    _clear_autobuild_state()
    src = _big_vcd(tmp_path)
    _settled(src)
    assert os.path.getsize(src) < va._AUTO_INDEX_MIN_BYTES
    snap = _run_cli(['--json', 'snapshot', str(src), '--at', '1'])
    assert snap.returncode == 0, snap.stderr
    assert 'background' not in snap.stderr
    assert sorted(p.name for p in tmp_path.iterdir()) == [src.name]


def test_background_build_log_only_on_failure(tmp_path, monkeypatch):
    """`index --auto` (the detached builder) writes <sidecar>.log only when
    it fails, and a later successful build removes it."""
    src = _big_vcd(tmp_path)
    _settled(src)
    log = Path(va.sidecar_path(src) + '.log')
    monkeypatch.setenv('VCD_ANALYZER_FAIL_INDEX', '1')
    failed = _run_cli(['index', str(src), '--auto'])
    assert failed.returncode == 1
    assert failed.stderr == ''  # detached: diagnostics go to the log
    assert 'simulated index failure' in log.read_text(encoding='utf-8')
    monkeypatch.delenv('VCD_ANALYZER_FAIL_INDEX')
    built = _run_cli(['index', str(src), '--auto'])
    assert built.returncode == 0, built.stderr
    assert va._sidecar_fresh(src, va.sidecar_path(src))
    assert not log.exists()


def test_auto_build_kill_switch(tmp_path, monkeypatch):
    monkeypatch.setenv('VCD_ANALYZER_AUTO_INDEX', '0')
    src = _big_vcd(tmp_path)
    _settled(src)
    snap = _run_cli(['--json', 'snapshot', str(src), '--at', '1'])
    assert snap.returncode == 0, snap.stderr
    assert not os.path.exists(va.sidecar_path(src))


def test_auto_build_skipped_for_live_writer(tmp_path):
    _clear_autobuild_state()
    src = _big_vcd(tmp_path)
    va.build_index(src, va.sidecar_path(src), 64)
    # bump the source mtime to NOW: looks like a simulator still writing
    os.utime(src)
    snap = _run_cli_any_size(['--json', 'snapshot', str(src), '--at', '1'])
    assert snap.returncode == 0, snap.stderr
    assert 'still being written' in snap.stderr or 'not rebuilt' in snap.stderr
    # and no rebuild happened: the stale sidecar is untouched
    assert not va._sidecar_fresh(src, va.sidecar_path(src))


def test_lock_single_flight_and_death_release(tmp_path):
    """OS-file-lock semantics: a held lock refuses second builders; a DEAD
    builder's lock is released by the OS (no pid parsing, no stale-file
    heuristics — an empty/garbage lock file is harmless)."""
    src = _big_vcd(tmp_path)
    sidecar = va.sidecar_path(src)
    fd = va._acquire_build_lock(sidecar)
    assert fd is not None
    try:
        assert va._acquire_build_lock(sidecar) is None  # second: refused
    finally:
        os.close(fd)  # death/release
    fd2 = va._acquire_build_lock(sidecar)
    assert fd2 is not None  # released on close
    os.close(fd2)
    # an EMPTY lock file (crash between create and write) is harmless
    Path(sidecar + '.lock').write_bytes(b'')
    fd3 = va._acquire_build_lock(sidecar)
    assert fd3 is not None
    os.close(fd3)





def test_writer_held_detected(tmp_path):
    src = _big_vcd(tmp_path)
    os.utime(src)  # fresh mtime = live writer signal
    assert va._writer_holds(src) is not None
    old = time.time() - 3600
    os.utime(src, (old, old))
    # no process holds it open in a test run (lsof finds nothing)
    assert va._writer_holds(src) is None


def _run_cli(args, env_extra=None):
    import subprocess
    from conftest import run_cli as _rc
    return _rc(args)


def test_small_file_never_loads_native_library(tmp_path, monkeypatch):
    """Order regression: a file below the size floor with no sidecar must
    be rejected by the size pre-filter BEFORE the native library load —
    small-file queries never pay lzma+dlopen."""
    monkeypatch.setattr(va, '_AUTO_SCRIPT_PATH', str(Path(__file__).resolve().parents[1] / 'vcd_analyzer.py'))
    small = tmp_path / 'tiny.vcd'
    small.write_text('$timescale 1ns $end $scope module top $end $var wire 1 ! a $end '
                     '$upscope $end $enddefinitions $end #0 0! #5 1!')
    old = time.time() - 3600
    os.utime(small, (old, old))
    va._warned.clear()
    called = []
    real = va._load_native_library
    monkeypatch.setattr(va, '_load_native_library',
                        lambda: called.append(1) or real())
    va.maybe_auto_build(va.VCDParser(str(small)), str(small))
    assert called == [], 'native library loaded for a sub-gate file'
    assert not os.path.exists(va.sidecar_path(small))


def test_gate_file_loads_native_last(tmp_path, monkeypatch):
    """The gate-passing path DOES reach the native loader (after all cheap
    checks) — the reorder must not have disabled auto-build entirely."""
    from test_index import _big_vcd
    monkeypatch.setattr(va, '_AUTO_SCRIPT_PATH', str(Path(__file__).resolve().parents[1] / 'vcd_analyzer.py'))
    monkeypatch.setattr(va, '_AUTO_INDEX_MIN_BYTES', 0)
    src = _big_vcd(tmp_path)
    old = time.time() - 3600
    os.utime(src, (old, old))
    va._warned.clear()
    called = []
    real = va._load_native_library
    monkeypatch.setattr(va, '_load_native_library',
                        lambda: called.append(1) or real())
    va.maybe_auto_build(va.VCDParser(str(src)), str(src))
    assert called, 'gate-passing file never reached the native loader'
