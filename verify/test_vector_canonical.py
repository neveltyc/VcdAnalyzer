import vcd_analyzer as va
from conftest import write_vcd, minimal_vcd, ns


def _vcd(tmp_path):
    return write_vcd(tmp_path, minimal_vcd(
        '$var reg 4 ! v [3:0] $end\n$var real 64 " r $end\n$var wire 1 # s $end\n',
        '#0\nb11 !\nr1.5 "\n0#\n#10\nb0011 !\nr1.5 "\n#20\nb1 !\n#30\nbx !\n#40\nb0x1 !\n'))


def test_short_vector_spellings_are_one_value(tmp_path):
    v = va.VCDParser(str(_vcd(tmp_path)))
    vals = [(t, val) for t, sid, val in v.iter_events() if sid == '!']
    # 'b11' then 'b0011' is a no-op re-assertion, not a change.
    assert vals == [(0, '0011'), (20, '0001'), (30, 'xxxx'), (40, '00x1')]
    reals = [val for _t, sid, val in v.iter_events() if sid == '"']
    assert reals == ['1.5']  # real values are never padded


def test_compare_and_summary_ignore_spelling(tmp_path, capsys):
    p = _vcd(tmp_path)
    v = va.VCDParser(str(p))
    va.cmd_compare(v, ns(at='5,15'))
    assert '0 changed' in capsys.readouterr().out
    rows, _undef, _counts = va._summary_rows(v, 0, None, v.match('v'))
    assert rows[0]['changes'] == 3


def test_begin_catch_up_uses_canonical_baseline(tmp_path):
    v = va.VCDParser(str(_vcd(tmp_path)))
    # The pre-window 'b11' and in-window 'b0011' are equal: nothing at #10.
    assert [t for t, sid, _ in v.iter_events(5, None, {'!'})] == [20, 30, 40]
