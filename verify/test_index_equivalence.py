"""Index-vs-parser equivalence over the parser's own torture corpus.

The index engine (items() tokenizer, pure-Python builder, embedded native
builder) is a SECOND and THIRD implementation of the data-section grammar,
so the parser's inline test grammars do not automatically cover it. This
suite mirrors every known-tricky shape from the parser tests — free-format
declarations, malformed operands, non-finite reals, bit-exploded offset
buses, extended-VCD ports, repeated timestamps, checkpoint re-assertions,
BOM/odd timescales, UTF-8 paths, adversarial garbage — and asserts that
python-built AND native-built sidecars answer exactly like the plain
parser: every state point, every transition window, every command output.
"""
import argparse
import contextlib
import io
import json
import os
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import vcd_analyzer as va

CORPUS = {
    # -- free-format declarations (from test_freeformat.py B1) -------------
    'freeformat_multidecl':
        '$timescale 1ns $end\n'
        '$scope module tb $end $scope module core $end\n'
        '$var wire 1 ! clk $end $var wire 1 " rst $end\n'
        '$upscope $end\n$upscope $end\n'
        '$enddefinitions $end\n#0\n0!\n0"\n#10\n1!\n1"\n',
    'freeformat_split_range':
        '$timescale 1ps $end $scope module top $end '
        '$var wire 8 ! data [ 7 : 0 ] $end $var wire 1 # en $end '
        '$upscope $end $enddefinitions $end '
        '#0 b10101010 ! 1# #10 xxxxxxxx ! 0#',
    'freeformat_tab_keywords':
        '$scope\tmodule\tm\t$end\n$var\twire\t1\t!\ta\t$end\n'
        '$enddefinitions\t$end\n#0\n0!\n#5\n1!\n',
    # -- malformed operand cascade (parser B4: no phantom events) ----------
    'rejected_token_cascade':
        '$timescale 1ns $end $scope module top $end $var wire 1 & q $end '
        '$var wire 4 # v $end $upscope $end $enddefinitions $end '
        '#0 b1012 1& b1 # 0& #10 1&',
    'bogus_section':
        '$timescale 1ns $end $scope module top $end $var wire 1 ! a $end '
        '$upscope $end $enddefinitions $end #0 0! '
        '$bogus #777 0! $end #10 1!',
    # -- non-finite reals (test_real_nonfinite.py shapes) -------------------
    'nonfinite_reals':
        '$timescale 1ns $end $scope module top $end $var real 64 $ r $end '
        '$var real 64 # s $end $upscope $end $enddefinitions $end '
        '#0 r0 $ rinf # #10 r-1.25 $ r-infinity # #20 rnan $ rnan(ind) # '
        '#30 r1e300 $ rnan(snan) # #40 r1.5e-9 $ rinf #',
    # -- bit-exploded offset / aliased buses (test_bit_bus_offset.py) -------
    'bit_bus_offset':
        '$timescale 1ns $end $scope module top $end '
        '$var wire 1 ! h [7] $end $var wire 1 " h [6] $end '
        '$var wire 1 # h [5] $end $var wire 1 $ h [4] $end '
        '$var wire 1 % h [3] $end $var wire 1 & lo $end '
        '$upscope $end $enddefinitions $end '
        '#0 1! 0" 1# 0$ 1% 0& #10 0! x" 1$ z% #20 1! 0" 1# 0$ 1%',
    'aliased_buses':
        '$timescale 1ns $end $scope module top $end '
        '$var wire 1 ! b [0] $end $var wire 1 " b [1] $end '
        '$var wire 1 ! standalone $end '
        '$var wire 1 ! aliasbus [0] $end $var wire 1 " aliasbus [1] $end '
        '$upscope $end $enddefinitions $end '
        '#0 x! x" 1! #10 0! 1" 1! 0! #20 0! 1" #30 b101 ! #40 1! 0"',
    'noncontiguous_bits':
        '$timescale 1ns $end $scope module top $end '
        '$var wire 1 ! bus [0] $end $var wire 1 " bus [5] $end '
        '$upscope $end $enddefinitions $end #0 0! 1" #10 1! 0"',
    # -- vector canonical spellings (test_vector_canonical.py) --------------
    'vector_canonical':
        '$timescale 1ns $end $scope module top $end '
        '$var wire 4 ! v $end $var wire 8 " w $end '
        '$upscope $end $enddefinitions $end '
        '#0 b1 ! b101 ! bx " b11 " #10 b0011 ! b00000001 " '
        '#20 b1010 ! bz " #30 b11 ! b1 "',
    # -- $dumpall/$dumpon checkpoint no-ops (test_dump_begin_noop.py) -------
    'dumpall_noop':
        '$timescale 1ps $end $scope module top $end $var wire 1 ! a $end '
        '$var wire 1 " b $end $upscope $end $enddefinitions $end '
        '#0 0! 0" $dumpall 0! 0" $end #10 1! $dumpall 1! 0" $end '
        '$dumpon 1! 0" $end #20 0! $dumpoff x! x" $end #30 1" $dumpon 1" 1! $end',
    # -- BOM / odd timescales (test_timescale_header.py shapes) -------------
    'bom_timescale':
        '\ufeff$timescale 10us $end\n$scope module top $end '
        '$var wire 1 ! a $end $upscope $end $enddefinitions $end #0 0! #7 1!',
    'dumpvars_no_leading_ts':
        '$scope module top $end $var wire 1 ! a $end $var wire 2 # v $end '
        '$upscope $end $enddefinitions $end $dumpvars 0! b0 # $end #10 1!',
    # -- late first event / absent signal ------------------------------------
    'late_first':
        '$scope module top $end $var wire 1 ! a $end '
        '$var wire 1 " absent $end $upscope $end $enddefinitions $end '
        '#100 0! #100 1! #200 0!',
    'single_tick_intra':
        '$scope module top $end $var wire 1 ! a $end $var event 1 " e $end '
        '$upscope $end $enddefinitions $end '
        '#0 ' + '0! 1! 0! 1" 1" ' * 80 + '#10 1!',
    'tick_repeat_bus':
        '$timescale 1ns $end $scope module top $end '
        '$var wire 1 ! b [0] $end $var wire 1 " b [1] $end '
        '$var wire 1 # s $end $upscope $end $enddefinitions $end '
        '#0 0! 0" 1# #5 1! #5 0! 1# #5 1" #10 1! 0" #10 0#',
    # -- extended VCD port records (research 'port' fixture) -----------------
    'port_records':
        '$timescale 1ns $end $scope module top $end '
        '$var port 2 ! p $end $var wire 1 " q $end '
        '$upscope $end $enddefinitions $end '
        '#0 p01 0 7 ! 0" #5 p10 7 0 ! 1" #10 p?1 0 0 ! #20',
    # -- UTF-8 paths / version ----------------------------------------------
    'utf8_paths':
        '$version 测试工具 $end $timescale 1ns $end $scope module top $end '
        '$var wire 1 ! 信号 $end $upscope $end $enddefinitions $end '
        '#0 0! #5 1!',
    # -- malformed + underscore timestamps -----------------------------------
    'malformed_ts':
        '$timescale 1ns $end $scope module top $end $var wire 1 ! a $end '
        '$var wire 4 " v $end $upscope $end $enddefinitions $end '
        '#0 0! b1 " #1.5 1! #10 b1011 " #1_0 0! #20 b0000 "',
    # -- reals + logic interleave -------------------------------------------
    'real_logic_mix':
        '$timescale 1ns $end $scope module top $end $var real 64 $ r $end '
        '$var wire 1 ! a $end $var integer 32 # n $end '
        '$upscope $end $enddefinitions $end '
        '#0 r3.14 $ 0! b0 # #10 r-2.5e3 $ 1! b1111 # #20 r1e-9 $ 0!',
}


def _write(tmp_path, name, text):
    p = tmp_path / (name + '.vcd')
    p.write_text(text, encoding='utf-8')
    return p


def _diff(raw, idx, path):
    """Full differential for one parser/index pair; returns checks count."""
    checks = 0
    times = sorted({t for t, _s, _v in raw.iter_events()} | {0, 1, 5, 10, 20})
    selections = [None] + ([{sorted(raw.signals)[0]}] if raw.signals else [])
    for selected in selections:
        for t in times:
            assert raw.state_at(t, selected) == idx.state_at(t, selected), \
                (path.name, 'state', t)
            checks += 1
        for begin, end in ((0, None), (times[0], times[len(times) // 2]),
                           (times[len(times) // 2], None)):
            assert (list(raw.iter_transitions(begin, end, selected))
                    == list(idx.iter_transitions(begin, end, selected))), \
                (path.name, 'transitions', begin, end)
            checks += 1
    return checks


def _commands_equal(raw, idx, path):
    base = {'at': '10', 'begin': '0', 'end': '20', 'filter': None,
            'limit': 500, 'verbose': False, 'json': True,
            'condition': [], 'show': []}
    chosen = next((i['path'] for s, i in sorted(raw.signals.items())
                   if raw._sid_kind[s] in ('scalar', 'vector', 'real')), None)
    specs = [('dump', {}), ('summary', {}), ('snapshot', {'at': '10'}),
             ('compare', {'at': '0,20'})]
    if chosen is not None:
        specs.append(('search', {'condition': [chosen + '=0']}))
        specs.append(('search', {'condition': ['changed(' + chosen + ')']}))
    for command, extra in specs:
        opts = argparse.Namespace(**{**base, **extra})

        def render(parser):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                getattr(va, 'cmd_' + command)(parser, opts)
            return out.getvalue()
        assert render(raw) == render(idx), (path.name, command, extra)


def _native_build(path, sidecar, block_bytes):
    env = dict(os.environ, VCD_ANALYZER_INDEX_THREADS='4',
               VCD_ANALYZER_INDEX_PARALLEL_MIN='1')
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update({k: v for k, v in env.items() if k != 'PATH'})
    try:
        return va.native_index_build(str(path), str(sidecar), block_bytes)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@pytest.mark.parametrize('block_bytes', [17, 4096])
def test_corpus_python_built_equivalence(tmp_path, block_bytes):
    total = 0
    for name, text in CORPUS.items():
        path = _write(tmp_path, name, text)
        raw = va.VCDParser(str(path))
        va.build_index(path, tmp_path / 'py.idx', block_bytes)
        idx = va.IndexedVCD(path, tmp_path / 'py.idx', enforce_gate=False)
        try:
            total += _diff(raw, idx, path)
            _commands_equal(raw, idx, path)
        finally:
            idx.close()
    assert total > 300


def test_corpus_native_built_equivalence(tmp_path):
    """The embedded native builder (forced 4 threads) must produce sidecars
    whose answers equal both the plain parser and the pure-Python build —
    including on the corpus shapes (or, for exotic tokens, by deferring
    to the pure-Python builder via the documented fallback)."""
    if va.native_index_build.__module__ is None:  # never: full file always
        pytest.skip('standard build')
    total = 0
    for name, text in CORPUS.items():
        path = _write(tmp_path, name, text)
        raw = va.VCDParser(str(path))
        stats = _native_build(path, tmp_path / 'n.idx', 64)
        va.build_index(path, tmp_path / 'p.idx', 64)
        a = va.IndexedVCD(path, tmp_path / 'p.idx', enforce_gate=False)
        b = va.IndexedVCD(path, tmp_path / 'n.idx', enforce_gate=False)
        try:
            total += _diff(raw, b, path)
            _diff(a, b, path)
            _commands_equal(raw, b, path)
        finally:
            a.close()
            b.close()
        assert stats is not None or os.path.getsize(tmp_path / 'n.idx') > 0
    assert total > 300


def _coarsening_budget(path, sidecar):
    """A budget that forces at least one pairwise block merge: the fixed
    part plus a quarter of the postings a fine build produced."""
    stats = va.build_index(path, sidecar, 17)
    fixed = va._sidecar_bytes(stats['blocks'], stats['raw_symbols'], 0)
    return stats, fixed + (stats['index_bytes'] - fixed) // 4


@pytest.mark.parametrize('builder', ['python', 'native'])
def test_corpus_coarsened_equivalence(tmp_path, builder):
    """Blocks merged to meet an index budget (the automatic block size)
    answer exactly like the plain parser, for both builders."""
    total = coarsened = 0
    for name, text in CORPUS.items():
        path = _write(tmp_path, name, text)
        raw = va.VCDParser(str(path))
        fine, budget = _coarsening_budget(path, tmp_path / 'fine.idx')
        sidecar = tmp_path / 'c.idx'
        if builder == 'python':
            stats = va.build_index(path, sidecar, 17, max_index_bytes=budget)
        else:
            stats = va.native_index_build(str(path), str(sidecar), 17, budget)
            if stats is None:
                pytest.skip('no native builder on this platform')
        if fine['blocks'] > 1:
            assert stats['coarsens'] >= 1, name
            assert stats['block_bytes'] == 17 << stats['coarsens']
            assert stats['index_bytes'] <= budget or stats['blocks'] == 1, name
            coarsened += 1
        idx = va.IndexedVCD(path, sidecar, enforce_gate=False)
        try:
            total += _diff(raw, idx, path)
            _commands_equal(raw, idx, path)
        finally:
            idx.close()
    assert coarsened >= 5 and total > 300


def test_unicode_digit_file_native_defers(tmp_path):
    """A '#٥' timestamp: the parser accepts it (int() takes Unicode digits),
    the native builder refuses — the native path must defer so the indexed
    answers still equal the plain parser."""
    path = tmp_path / 'uni.vcd'
    path.write_text('$timescale 1ns $end $scope module top $end '
                    '$var wire 1 ! a $end $upscope $end $enddefinitions $end '
                    '#0 0! #٥ 1! #20 0!', encoding='utf-8')
    raw = va.VCDParser(str(path))
    assert any(t == 5 for t, _s, _v in raw.iter_events())
    sidecar = tmp_path / 'uni.idx'
    # native-level call refuses; build_index_best defers and still succeeds
    stats = va.build_index_best(str(path), str(sidecar), 64)
    idx = va.IndexedVCD(path, sidecar, enforce_gate=False)
    try:
        assert stats['builder'] in ('python', 'native')
        _diff(raw, idx, path)
    finally:
        idx.close()


def test_native_wide_postings_over_64k_blocks(tmp_path):
    """nblocks > 65535 forces the 8-byte wide posting mode (mode 0) in the
    native builder; the reader must answer identically."""
    path = tmp_path / 'wide.vcd'
    syms = [chr(33 + i % 94) + ('' if i < 94 else chr(33 + i // 94)) for i in range(8)]
    chunk = ''.join('{}{}\n'.format('01'[i % 2], s) for i, s in enumerate(syms))
    with open(path, 'w') as out:
        out.write('$timescale 1ps $end $scope module top $end')
        for s in syms:
            out.write('$var wire 1 {} {} $end'.format(s, s.replace('!', 'q')))
        out.write('$upscope $end $enddefinitions $end\n')
        t = 0
        while path.stat().st_size < 300 << 10:
            out.write('#%d\n%s' % (t, chunk))
            t += 2
    stats = _native_build(path, tmp_path / 'wide.idx', 1)  # 1-byte blocks
    assert stats is not None and stats['blocks'] > 65535
    assert stats['posting_mode'] == 0
    idx = va.IndexedVCD(path, tmp_path / 'wide.idx', enforce_gate=False)
    raw = va.VCDParser(str(path))
    try:
        span = idx.blocks[-1][3]
        for frac in (10, 50, 90):
            a = span * frac // 100
            assert (list(raw.iter_transitions(a, a + max(1, span // 100), None))
                    == list(idx.iter_transitions(a, a + max(1, span // 100), None)))
    finally:
        idx.close()


def test_random_garbage_data_section(tmp_path):
    """Random printable bytes after a valid header: the parser tolerates
    everything; the indexed answers must not differ."""
    rng = random.Random(20261025)
    path = tmp_path / 'garbage.vcd'
    body = bytes(rng.randrange(33, 127) for _ in range(20000))
    with open(path, 'wb') as out:
        out.write(b'$timescale 1ns $end $scope module top $end '
                  b'$var wire 1 ! a $end $var wire 4 " v $end '
                  b'$upscope $end $enddefinitions $end\n')
        out.write(body.replace(b'\n', b' '))
    raw = va.VCDParser(str(path))
    va.build_index(path, tmp_path / 'g.idx', 97)
    idx = va.IndexedVCD(path, tmp_path / 'g.idx', enforce_gate=False)
    try:
        assert _diff(raw, idx, path) > 0
    finally:
        idx.close()


def test_corrupt_directory_flags_byte(tmp_path):
    src = tmp_path / 'x.vcd'
    src.write_text('$timescale 1ns $end $scope module top $end $var wire 1 ! a $end '
                   '$upscope $end $enddefinitions $end #0 0! #5 1!')
    va.build_index(src, tmp_path / 'c.idx', 64)
    data = bytearray((tmp_path / 'c.idx').read_bytes())
    data[-1] = 0x63  # 'c' — invalid posting mode
    (tmp_path / 'c.idx').write_bytes(bytes(data))
    os.replace(tmp_path / 'c.idx', va.sidecar_path(src))
    va._warned.clear()
    assert va.try_index(src) is None  # KeyError path: clean fallback


def test_hostile_builder_errors_are_clean(tmp_path):
    from conftest import run_cli
    header = (b'$timescale 1ns $end $scope module top $end $var wire 1 ! a $end '
              b'$upscope $end $enddefinitions $end\n')
    cases = {
        'longtoken': header + b'#0\n0!' + b'1' * (2 << 20) + b'\n',
        'hugetimestamp': header + b'#' + b'9' * 200 + b'\n0!',
    }
    for name, blob in cases.items():
        p = tmp_path / (name + '.vcd')
        p.write_bytes(blob)
        result = run_cli(['index', str(p)])
        assert result.returncode != 0, name
        assert 'Traceback' not in result.stderr, name
        assert not os.path.exists(va.sidecar_path(p)), name


@pytest.mark.parametrize('builder', ['python', 'native'])
def test_coarsening_stops_at_the_block_cap(tmp_path, builder):
    """Over budget, merging still stops at max_block_bytes: an index whose
    directory alone exceeds the budget must not merge down to one block."""
    path = _write(tmp_path, 'many.vcd', CORPUS[sorted(CORPUS)[0]])
    for name, text in CORPUS.items():
        candidate = _write(tmp_path, 'c.vcd', text)
        if va.build_index(candidate, tmp_path / 'probe.idx', 17)['blocks'] >= 8:
            path = _write(tmp_path, 'many.vcd', text)
            break
    sidecar = tmp_path / 'capped.idx'
    if builder == 'python':
        stats = va.build_index(path, sidecar, 17, max_index_bytes=1, max_block_bytes=68)
    else:
        stats = va.native_index_build(str(path), str(sidecar), 17, 1, 68)
        if stats is None:
            pytest.skip('no native builder on this platform')
    assert stats['block_bytes'] == 68 and stats['coarsens'] == 2
    assert stats['blocks'] > 1
    assert stats['data_start'] > 0
    raw = va.VCDParser(str(path))
    idx = va.IndexedVCD(path, sidecar, enforce_gate=False)
    try:
        _diff(raw, idx, path)
    finally:
        idx.close()
