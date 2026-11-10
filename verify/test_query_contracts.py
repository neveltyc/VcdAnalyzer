"""Query contracts that must not silently degrade.

* Windowed queries start at the window: the change stream hands over the
  settled state before t0 (`baseline`), identically on the plain parser,
  the index decoder and the index's plain-scan hand-off.
* `--filter`, `--show` and `--condition` share one matcher: an exact full
  path selects that signal only.
* A question the file cannot answer is an error, not "no match": a target
  wider than the signal, a bit pattern against a real, a non-VCD input.
* A time-regressing dump is answered with a warning.
* Exit status is grep-style: search 0 = found, 1 = nothing found; 2 = error.
"""
import pytest

import vcd_analyzer as va
from conftest import load_json_stdout, minimal_vcd, run_cli, write_vcd


DECLS = ('$var wire 1 ! sig3 $end\n'
         '$var wire 1 " sig30 $end\n'
         '$var wire 1 # sig31 $end\n'
         '$var wire 4 $ state $end\n'
         '$var real 64 % temp $end\n')
DATA = ('#0\n0!\n0"\n0#\nb0 $\nr1.5 %\n'
        '#10\n1!\n1"\nb101 $\nr5 %\n'
        '#20\n0!\nb11 $\n'
        '#30\n1#\n')


@pytest.fixture
def vcd(tmp_path):
    return write_vcd(tmp_path, minimal_vcd(DECLS, DATA, scope='top'))


# --- windowed streams: baseline -----------------------------------------------

def _stream(parser, t0, t1, sids):
    base = {}
    rows = list(parser.iter_transitions(t0, t1, sids, base))
    return base, rows


@pytest.mark.parametrize('ratio', [0.0, float('inf')])  # hand-off / decoder
def test_index_baseline_matches_plain_on_both_paths(tmp_path, monkeypatch, ratio):
    src = write_vcd(tmp_path, minimal_vcd(DECLS, DATA * 1, scope='top'))
    raw = va.VCDParser(str(src))
    va.build_index(src, tmp_path / 's.idx', 17)
    idx = va.IndexedVCD(src, tmp_path / 's.idx', enforce_gate=False)
    monkeypatch.setattr(va.IndexedVCD, 'SOURCE_SCAN_RATIO', ratio)
    try:
        for sids in (None, {'!'}, {'$', '%'}):
            for t0 in (0, 5, 10, 11, 25, 30, 99):
                for t1 in (t0, t0 + 10, None):
                    want = _stream(raw, t0, t1, sids)
                    assert want[0] == raw.state_before(t0, sids), (sids, t0)
                    assert _stream(idx, t0, t1, sids) == want, (sids, t0, t1)
    finally:
        idx.close()


def test_baseline_for_window_past_the_end_is_the_final_state(vcd):
    raw = va.VCDParser(str(vcd))
    base, rows = _stream(raw, 1000, None, None)
    assert rows == [] and base == raw.state_at(1000)


def test_search_window_agrees_with_full_replay(vcd):
    # Spans clipped to a late window equal the full-file spans clipped.
    full = run_cli(['--json', 'search', vcd, '--condition', 'top.sig3=1'])
    late = run_cli(['--json', 'search', vcd, '--condition', 'top.sig3=1',
                    '--begin', '15'])
    spans = [(r['begin_ticks'], r['end_ticks'])
             for r in load_json_stdout(full.stdout)['intervals']]
    clipped = [(max(a, 15), b) for a, b in spans if b > 15]
    assert [(r['begin_ticks'], r['end_ticks'])
            for r in load_json_stdout(late.stdout)['intervals']] == clipped


# --- one matcher: exact full path first ---------------------------------------

def test_filter_exact_path_selects_only_that_signal(vcd):
    v = va.VCDParser(str(vcd))
    paths = lambda pats: sorted(v.signals[s]['path'] for s in v.match(pats))
    assert paths(['top.sig3']) == ['top.sig3']
    assert paths(['TOP.SIG3']) == ['top.sig3']
    assert paths(['top.sig3*']) == ['top.sig3', 'top.sig30', 'top.sig31']
    assert paths(['sig3']) == ['top.sig3', 'top.sig30', 'top.sig31']
    assert paths(['top.sig3', 'state']) == ['top.sig3', 'top.state']


def test_filter_show_and_condition_agree(vcd):
    listed = run_cli(['--json', 'list', vcd, '--filter', 'top.sig3'])
    assert [s['path'] for s in load_json_stdout(listed.stdout)['signals']] == ['top.sig3']
    shown = run_cli(['--json', 'search', vcd, '--condition', 'top.sig3=1',
                     '--show', 'top.sig3'])
    assert load_json_stdout(shown.stdout)['show'] == ['top.sig3']


# --- unanswerable questions are errors ----------------------------------------

@pytest.mark.parametrize('cond', ['top.state=99', 'top.state!=16', 'top.state=b11111',
                                  'top.state=0x10', 'top.sig3=2'])
def test_target_wider_than_signal_is_an_error(vcd, cond):
    r = run_cli(['search', vcd, '--condition', cond])
    assert r.returncode == 2 and 'does not fit' in r.stderr, r.stderr


@pytest.mark.parametrize('cond', ['top.temp=b101', 'top.temp=0b101', 'top.temp=0x5'])
def test_bit_spelling_against_real_is_an_error(vcd, cond):
    r = run_cli(['search', vcd, '--condition', cond])
    assert r.returncode == 2 and 'against a bit pattern' in r.stderr, r.stderr


def test_decimal_against_real_still_matches(vcd):
    r = run_cli(['--json', 'search', vcd, '--condition', 'top.temp=5'])
    assert r.returncode == 0, r.stderr
    assert load_json_stdout(r.stdout)['intervals'][0]['begin_ticks'] == 10


@pytest.mark.parametrize('content', [b'hello world\nthis is not a vcd\n',
                                     bytes(range(256)) * 8, b''])
def test_non_vcd_input_is_an_error(tmp_path, content):
    junk = tmp_path / 'junk.vcd'
    junk.write_bytes(content)
    for cmd in (['info'], ['list'], ['dump']):
        r = run_cli(cmd + [junk])
        assert r.returncode == 2, (cmd, r.stdout, r.stderr)
        assert 'is not a VCD file' in r.stderr or 'exceeds' in r.stderr, r.stderr


def test_vcd_with_empty_dump_is_still_accepted(tmp_path):
    src = write_vcd(tmp_path, '$timescale 1ns $end\n$enddefinitions $end\n')
    assert run_cli(['info', src]).returncode == 0


# --- time order ---------------------------------------------------------------

def test_time_regression_is_warned_once(tmp_path):
    src = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! a $end\n', '#0\n0!\n#20\n1!\n#10\n0!\n#5\n1!\n#30\n0!\n'))
    for cmd in (['dump', src], ['summary', src], ['search', src, '--condition', 'tb.a=1']):
        r = run_cli(cmd)
        assert r.stderr.count('timestamps go backwards') == 1, (cmd, r.stderr)
        assert '#10 after #20' in r.stderr


def test_ordered_file_has_no_time_warning(vcd):
    assert 'backwards' not in run_cli(['dump', vcd]).stderr


# --- exit status --------------------------------------------------------------

@pytest.mark.parametrize('extra', [[], ['--json']])
def test_search_exit_status(vcd, tmp_path, extra):
    found = run_cli(extra + ['search', vcd, '--condition', 'top.sig3=1'])
    none = run_cli(extra + ['search', vcd, '--condition', 'top.state=7'])
    edge_none = run_cli(extra + ['search', vcd, '--condition', 'changed(top.state)',
                                 '--begin', '25'])
    bad = run_cli(extra + ['search', vcd, '--condition', 'top.nosuch=1'])
    assert (found.returncode, none.returncode, edge_none.returncode, bad.returncode) \
        == (0, 1, 1, 2), (found.stderr, none.stderr, edge_none.stderr, bad.stderr)
    assert none.stderr == '' and none.stdout  # an answer, not an error
    out = tmp_path / 'r.txt'
    to_file = run_cli(extra + ['search', vcd, '--condition', 'top.state=7', '-o', out])
    assert to_file.returncode == 1 and out.exists()


def test_other_commands_exit_zero_on_empty_results(vcd):
    assert run_cli(['dump', vcd, '--begin', '25', '--end', '26']).returncode == 0


def test_errors_exit_two(vcd, tmp_path):
    assert run_cli(['dump', vcd, '--begin', 'bad']).returncode == 2
    assert run_cli(['info', tmp_path / 'missing.vcd']).returncode == 2
    assert run_cli(['index', vcd, '--threads', '0']).returncode == 2


# --- native builder parameters --------------------------------------------------

def test_threads_reach_the_native_builder_as_an_argument(tmp_path, monkeypatch):
    src = write_vcd(tmp_path, minimal_vcd(DECLS, DATA, scope='top'))
    monkeypatch.delenv('VCD_ANALYZER_INDEX_THREADS', raising=False)
    import os
    before = dict(os.environ)
    stats = va.build_index_best(str(src), str(tmp_path / 'a.vcidx'), threads=3)
    assert dict(os.environ) == before
    if stats['builder'] != 'native':
        pytest.skip('no native builder on this platform')
    # A tiny file stays single-threaded below parallel_min, whatever is asked.
    assert stats['threads'] == 1
    stats = va.native_index_build(str(src), str(tmp_path / 'b.vcidx'), 1 << 20,
                                  threads=2, parallel_min=1)
    assert stats['threads'] >= 1
