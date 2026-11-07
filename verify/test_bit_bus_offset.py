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


def _ident(i):
    out = ''
    i += 1
    while i:
        i, r = divmod(i - 1, 94)
        out += chr(33 + r)
    return out


def _sparse_exploded_bus(tmp_path, width, ticks):
    """A bit-exploded bus where each tick flips ONE bit — the shape that
    made per-tick bus assembly O(width)."""
    ids = [_ident(i) for i in range(width)]
    decls = ''.join('$var wire 1 {} hot [{}] $end\n'.format(c, i) for i, c in enumerate(ids))
    data = ['#0\n'] + ['0{}\n'.format(c) for c in ids]
    for t in range(1, ticks + 1):
        data.append('#{}\n{}{}\n'.format(t, (t // width) & 1 ^ 1, ids[t % width]))
    return write_vcd(tmp_path, minimal_vcd(decls, ''.join(data)), 'w{}.vcd'.format(width))


def test_wide_exploded_bus_values(tmp_path):
    p = _sparse_exploded_bus(tmp_path, 200, 450)
    v = va.VCDParser(str(p))
    sid = next(iter(v.signals))
    assert v.signals[sid]['width'] == 200
    # reference model: one bit written per tick, no-op ticks emit nothing
    bits = ['0'] * 200
    expected = [(0, '0' * 200)]
    for t in range(1, 451):
        bits[t % 200] = str((t // 200) & 1 ^ 1)
        value = ''.join(reversed(bits))
        if value != expected[-1][1]:
            expected.append((t, value))
    assert [(t, val) for t, _s, val in v.iter_events()] == expected
    assert v.state_at(450)[sid] == expected[-1][1]
    assert v.state_at(199)[sid] == '1' * 199 + '0'


def test_wide_exploded_bus_cost_independent_of_width(tmp_path):
    """Same number of single-bit ticks on a 64-bit and a 4096-bit exploded
    bus: assembling each tick's value must not cost O(width) Python work
    (it did — ~7x slower at 4096 bits, now within noise)."""
    import time

    def cost(width):
        v = va.VCDParser(str(_sparse_exploded_bus(tmp_path, width, 20000)))
        best = None
        for _ in range(3):
            start = time.perf_counter()
            v.state_at(10 ** 9)
            elapsed = time.perf_counter() - start
            best = elapsed if best is None else min(best, elapsed)
        return best
    assert cost(4096) < 3.0 * cost(64)  # ~1.3 now, ~7 before
