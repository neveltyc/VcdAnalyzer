"""Differential tests for the optional .vcidx block-index sidecar.

The index reader must be indistinguishable from the plain parser: every
command's output, every state_at/iter_transitions window, for every
selection — across block sizes, gate outcomes, stale sidecars and the
kill switches. The pure-Python builder is exercised here; the embedded native
builder's equivalent matrix lives in test_index_fast.py.
"""
import argparse
import contextlib
import io
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vcd_analyzer as va


FIXTURES = sorted((Path(__file__).parent / 'fixtures').glob('*.vcd')) + \
           sorted((Path(__file__).parent / 'samples').glob('*.vcd'))

GRAMMARS = {
    'idx_bits': '$timescale 1ns $end $scope module top $end '
                '$var wire 1 ! b [0] $end $var wire 1 " b [1] $end '
                '$var wire 1 ! standalone $end '
                '$upscope $end $enddefinitions $end '
                '#0 x! x" 1! #10 0! 1" 1! 0! #20 0! 1" #30 b101 ! #40 1! 0"',
    'idx_repeat': '$timescale 1ns $end $scope module top $end '
                  '$var wire 1 ! b [0] $end $var wire 1 " b [1] $end '
                  '$var wire 1 # s $end $upscope $end $enddefinitions $end '
                  '#0 0! 0" 1# #5 1! #5 0! 1# #5 1" #10 1! 0" #10 0#',
    'idx_real_event': '$timescale 1ns $end $scope module top $end '
                      '$var real 64 $ r $end $var event 1 % ev $end '
                      '$var wire 4 # v $end $upscope $end $enddefinitions $end '
                      '#0 r0 $ 1% b1 # #10 r-1.25 $ 1% b11 # #20 rnan(ind) $ b1 #30',
}


def _fixtures(tmp_path):
    out = list(FIXTURES)
    for name, text in GRAMMARS.items():
        p = tmp_path / (name + '.vcd')
        p.write_text(text)
        out.append(p)
    return out


def _times_and_selections(raw):
    times = {0, 1, 4, 5, 9, 10, 11, 19, 20, 21, 30}
    times.update(t for t, _sid, _v in raw.iter_events())
    times = sorted(times)
    selections = [None] + [{sid} for sid in sorted(raw.signals)[:6]]
    return times, selections


@pytest.mark.parametrize('block_size', [17, 4096])
def test_index_differential(tmp_path, block_size):
    checks = 0
    for i, path in enumerate(_fixtures(tmp_path)):
        raw = va.VCDParser(str(path))
        times, selections = _times_and_selections(raw)
        sidecar = tmp_path / f'fx{i}-{block_size}.idx'
        va.build_index(path, sidecar, block_size)
        idx = va.IndexedVCD(path, sidecar, enforce_gate=False)
        try:
            for selected in selections:
                for t in times:
                    assert raw.state_at(t, selected) == idx.state_at(t, selected), \
                        (path.name, 'state_at', t)
                    checks += 1
                for begin, end in ((0, None), (times[0], times[len(times)//2]),
                                   (times[len(times)//2], None)):
                    assert list(raw.iter_transitions(begin, end, selected)) == \
                           list(idx.iter_transitions(begin, end, selected)), \
                        (path.name, 'transitions', begin, end)
                    checks += 1
        finally:
            idx.close()
    assert checks > 100


def _render(parser, command, options):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        getattr(va, 'cmd_' + command)(parser, options)
    return out.getvalue()


def test_indexed_commands_match_plain(tmp_path):
    options = argparse.Namespace(at='10', begin='5', end='20', filter=None,
                                  limit=500, verbose=False, json=True,
                                  condition=[], show=[])
    for i, path in enumerate(FIXTURES):
        raw = va.VCDParser(str(path))
        sidecar = tmp_path / f'cmd{i}.idx'
        va.build_index(path, sidecar, 64)
        idx = va.IndexedVCD(path, sidecar, enforce_gate=False)
        try:
            chosen = next((info['path'] for sid, info in sorted(raw.signals.items())
                           if raw._sid_kind[sid] in ('scalar', 'vector')), None)
            specs = [('dump', {}), ('summary', {}),
                     ('snapshot', {'at': '10'}), ('compare', {'at': '10,20'})]
            if chosen is not None:
                specs.append(('search', {'condition': [chosen + '=0']}))
                specs.append(('search', {'condition': ['changed(' + chosen + ')']}))
            for command, extra in specs:
                merged = vars(options).copy()
                merged.update(extra)
                opts = argparse.Namespace(**merged)
                assert _render(raw, command, opts) == _render(idx, command, opts), \
                    (path.name, command, extra)
        finally:
            idx.close()


def test_gate_rejects_header_heavy(tmp_path):
    # 3000 declared symbols over ~2 KiB of data: the index costs more than
    # the scan it replaces, so try_index must refuse and answer via the
    # plain parser (results still identical).
    def code(n):  # 3-char printable id codes, unique for n < 94**3
        return ''.join(chr(33 + (n // 94**k) % 94) for k in (2, 1, 0))

    path = tmp_path / 'heavy.vcd'
    with open(path, 'w') as out:
        out.write('$timescale 1ns $end $scope module top $end')
        for n in range(3000):
            out.write('$var wire 1 {} s{} $end'.format(code(n), n))
        out.write('$upscope $end $enddefinitions $end #0 ')
        for n in range(50):
            out.write('{}{} '.format('01'[n % 2], code(n)))
        out.write('#10 0' + code(0))
    va.build_index(path, tmp_path / 'heavy.idx', 1024)
    wrapped = va.try_index(path)
    try:
        assert wrapped is None
        plain = va.VCDParser(str(path))
        assert plain.state_at(10) == {sym: '0' for sym in plain.signals}
    finally:
        if wrapped is not None:
            wrapped.close()


def _big_vcd(tmp_path):
    """A file that passes the usage gate (>=128 KiB data, >=64 B/symbol)."""
    path = tmp_path / 'big.vcd'
    with open(path, 'w') as out:
        out.write('$timescale 1ns $end $scope module top $end '
                  '$var wire 1 ! a $end $var wire 4 " v $end $upscope $end '
                  '$enddefinitions $end\n')
        chunk = ('1! 0! b1 " b0 " 0!\n')
        out.write('#0\n')
        t = 0
        while path.stat().st_size < 200 << 10:
            out.write('#%d\n%s' % (t, chunk * 20))
            t += 5
    return path


def test_stale_sidecar_falls_back(tmp_path, capsys):
    # A sidecar whose size/mtime no longer match the source must be ignored
    # with exactly one stderr warning.
    src = _big_vcd(tmp_path)
    va.build_index(src, va.sidecar_path(src), 64)
    assert va.try_index(src) is not None
    os.utime(src, ns=(os.stat(src).st_atime_ns, os.stat(src).st_mtime_ns + 1_000_000))
    va._warned.clear()  # warnings dedupe per category; reset to observe this one
    wrapped = va.try_index(src)
    try:
        assert wrapped is None
        captured = capsys.readouterr()
        assert 'ignoring' in captured.err and 'vcidx' in captured.err
    finally:
        if wrapped is not None:
            wrapped.close()


def test_no_index_switch(tmp_path, monkeypatch):
    path = _big_vcd(tmp_path)
    va.build_index(path, va.sidecar_path(path), 64)
    assert va.try_index(path) is not None  # would upgrade without the switch
    monkeypatch.setenv('VCD_ANALYZER_NO_INDEX', '1')
    try:
        assert va.try_index(path) is None
    finally:
        monkeypatch.delenv('VCD_ANALYZER_NO_INDEX')


def test_non_monotonic_rejected_cleanly(tmp_path, capsys):
    from conftest import run_cli
    path = tmp_path / 'regress.vcd'
    path.write_text('$scope module top $end $var wire 1 ! a $end $upscope $end '
                    '$enddefinitions $end #10 0! #5 1!')
    result = run_cli(['index', str(path)])
    assert result.returncode != 0
    assert 'non-monotonic' in result.stderr
