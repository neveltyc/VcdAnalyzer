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


def test_auto_build_spawn(tmp_path):
    _clear_autobuild_state()
    src = _big_vcd(tmp_path)
    _settled(src)
    snap = _run_cli(['--json', 'snapshot', str(src), '--at', '1'])
    assert snap.returncode == 0, snap.stderr
    assert 'building index in the background' in snap.stderr
    sidecar = Path(va.sidecar_path(src))
    for _ in range(100):  # background build of a ~200 KiB file is instant
        if sidecar.exists() and va._sidecar_fresh(src, str(sidecar)):
            break
        time.sleep(0.1)
    assert sidecar.exists(), 'background build never produced the sidecar'
    # the lock must be gone once the builder finishes
    for _ in range(100):
        if not os.path.exists(str(sidecar) + '.lock'):
            break
        time.sleep(0.1)
    assert not os.path.exists(str(sidecar) + '.lock')


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
    snap = _run_cli(['--json', 'snapshot', str(src), '--at', '1'])
    assert snap.returncode == 0, snap.stderr
    assert 'still being written' in snap.stderr or 'not rebuilt' in snap.stderr
    # and no rebuild happened: the stale sidecar is untouched
    assert not va._sidecar_fresh(src, va.sidecar_path(src))


def test_lock_dead_owner_reclaimed(tmp_path):
    """A lock whose owner PID is gone and whose mtime is ancient is
    reclaimed by _acquire_build_lock itself — no manual unlink."""
    src = _big_vcd(tmp_path)
    sidecar = va.sidecar_path(src)
    lock = sidecar + '.lock'
    with open(lock, 'w') as f:
        f.write('999999999')  # not a live PID
    old = time.time() - 7200
    os.utime(lock, (old, old))
    got = va._acquire_build_lock(sidecar)
    assert got == lock  # reclaimed on the first attempt, in-function
    os.unlink(got)


def test_lock_single_flight(tmp_path):
    src = _big_vcd(tmp_path)
    sidecar = va.sidecar_path(src)
    lock = va._acquire_build_lock(sidecar)
    assert lock is not None
    assert va._acquire_build_lock(sidecar) is None  # second builder: refused
    # a dead owner's lock is reclaimed
    with open(lock, 'w') as f:
        f.write('999999999')
    os.utime(lock, (time.time() - 7200, time.time() - 7200))
    os.unlink(lock)
    lock2 = va._acquire_build_lock(sidecar)
    assert lock2 is not None
    os.unlink(lock2)


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
