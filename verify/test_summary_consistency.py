import vcd_analyzer as va
from conftest import write_vcd, minimal_vcd, ns, load_json_stdout


def _vcd(tmp_path):
    return write_vcd(tmp_path, minimal_vcd(
        '$var event 1 ! ev $end\n$var wire 1 " late $end\n$var wire 1 # a $end\n'
        '$var wire 1 $ once $end\n',
        '#0\n0#\n1!\n#5\n1!\n#10\n1!\n1"\n#15\n1!\n1#\n1$\n#20\n0"\n'))


def _rows(capsys, v, **kw):
    va.cmd_summary(v, ns(json=True, **kw))
    return {r['path']: r for r in load_json_stdout(capsys.readouterr().out)['rows']}


def _search_count(capsys, v, sig, **kw):
    va.cmd_search(v, ns(json=True, condition=['changed({})'.format(sig)], **kw))
    return load_json_stdout(capsys.readouterr().out)['total']


def test_summary_counts_match_search_changed(tmp_path, capsys):
    v = va.VCDParser(str(_vcd(tmp_path)))
    rows = _rows(capsys, v)
    for sig in ('ev', 'late', 'a', 'once'):
        assert rows['tb.' + sig]['changes'] == _search_count(capsys, v, 'tb.' + sig), sig
    assert rows['tb.ev']['changes'] == 4          # every trigger, including #0
    assert rows['tb.ev']['rise_count'] is None
    assert rows['tb.late']['changes'] == 1        # 1->0 only
    assert rows['tb.late']['defined_at_ticks'] == 10
    assert rows['tb.once']['kind'] == 'static'    # defined once, never changed
    assert rows['tb.once']['value'] == '1'


def test_summary_window_counts_match_search(tmp_path, capsys):
    v = va.VCDParser(str(_vcd(tmp_path)))
    rows = _rows(capsys, v, begin='5', end='15')
    for sig in ('ev', 'late', 'a'):
        assert rows['tb.' + sig]['changes'] == _search_count(
            capsys, v, 'tb.' + sig, begin='5', end='15'), sig
