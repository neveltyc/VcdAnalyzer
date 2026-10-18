import vcd_analyzer as va
from conftest import write_vcd, minimal_vcd


def test_offset_bit_run_reassembles_as_part_select(tmp_path):
    decls = ''.join('$var wire 1 {} bus [{}] $end\n'.format(c, i)
                    for c, i in zip('!"#$', range(8, 12)))
    p = write_vcd(tmp_path, minimal_vcd(decls, '#0\n0!\n1"\n0#\n1$\n#5\n1!\n'))
    v = va.VCDParser(str(p))
    paths = sorted(i['path'] for i in v.signals.values())
    assert paths == ['tb.bus[11:8]']
    sid = next(iter(v.signals))
    assert v.signals[sid]['width'] == 4
    assert [(t, val) for t, _s, val in v.iter_events()] == [(0, '1010'), (5, '1011')]


def test_gapped_or_single_bits_stay_individual(tmp_path):
    p = write_vcd(tmp_path, minimal_vcd(
        '$var wire 1 ! g [3] $end\n$var wire 1 " g [5] $end\n'
        '$var wire 1 # one [4] $end\n', '#0\n0!\n1"\n1#\n'))
    v = va.VCDParser(str(p))
    assert sorted(i['path'] for i in v.signals.values()) == [
        'tb.g[3]', 'tb.g[5]', 'tb.one[4]']
