"""Don't-care bits ('?') in binary condition targets.

Conditions compare whole values, so "bit 2 of status is 1" -- 128 distinct
values on an 8-bit bus -- could not be asked at all; the only route was to dump
the whole bus and decode it outside the tool, which runs into --limit on long
traces. A '?' bit, as in a Verilog casez item, matches any value and leaves
the other bits exact.

The fixture follows the shape iverilog writes: a vector dump drops redundant
leading zeros (`b10` for 8'h02) and compresses an x run (`b1xxxx` for
8'b0001_xxxx), so every comparison runs on the left-extended value.
"""
import contextlib
import io

import pytest

import vcd_analyzer as va
from conftest import load_json_stdout, minimal_vcd, ns, run_cli, write_vcd


DECLS = ('$var reg 8 ! bus $end\n'
         '$var real 1 " r $end\n'
         '$var wire 1 # bit $end\n')
DATA = ('#0\nb0 !\nr0 "\n0#\n'
        '#10\nb10 !\n'          # 0x02
        '#20\nb1010 !\n1#\n'    # 0x0a
        '#40\nb1xxxx !\n'       # 0001_xxxx
        '#50\nb10000100 !\n')   # 0x84


@pytest.fixture
def vcd(tmp_path):
    return write_vcd(tmp_path, minimal_vcd(DECLS, DATA))


def search(vcd_path, *conditions):
    v = va.VCDParser(str(vcd_path))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        va.cmd_search(v, ns(json=True, condition=list(conditions),
                            begin='0ns', end='60ns'))
    return load_json_stdout(buf.getvalue())


def spans(res):
    return [(r['begin_ticks'], r['end_ticks']) for r in res['intervals']]


# --- equality ---------------------------------------------------------------

def test_single_bit_mask(vcd):
    # bit 1 is set in 0x02 and 0x0a; unknown-free elsewhere is irrelevant.
    assert spans(search(vcd, 'bus=b??????1?')) == [(10, 40)]


def test_mask_matches_bits_beside_an_x_run(vcd):
    # 0001_xxxx: bit 4 is a known 1 even though the low nibble is x.
    assert spans(search(vcd, 'bus=b???1????')) == [(40, 50)]


def test_cared_x_bit_does_not_match_a_known_bit(vcd):
    # bit 3 is x at 40ns, so it is not a 1 there.
    assert spans(search(vcd, 'bus=b????1???')) == [(20, 40)]


def test_mask_can_require_an_x(vcd):
    assert spans(search(vcd, 'bus=b????x???')) == [(40, 50)]


def test_multi_bit_field(vcd):
    # top bit 1 and bit 2 set: only 0x84.
    assert spans(search(vcd, 'bus=b1????1??')) == [(50, 60)]


def test_short_mask_pads_with_zero(vcd):
    # b1??? on 8 bits is 0000_1???: the high nibble must be 0.
    assert spans(search(vcd, 'bus=b1???')) == [(20, 40)]


def test_all_dont_care_matches_every_observed_value(vcd):
    assert spans(search(vcd, 'bus=b????????')) == [(0, 60)]


def test_0b_prefix_and_one_bit_signal(vcd):
    assert spans(search(vcd, 'bus=0b??????1?')) == spans(search(vcd, 'bus=b??????1?'))
    assert spans(search(vcd, 'bit=b?')) == [(0, 60)]


def test_over_wide_mask_trims_dont_care_and_zero_excess(vcd):
    assert spans(search(vcd, 'bus=b?0??????1?')) == [(10, 40)]
    v = va.VCDParser(str(vcd))
    (c,) = va._resolve_conditions(v, 'bus=b?0??????1?')
    assert c['target_raw'] == '??????1?'


def test_over_wide_mask_with_a_set_excess_bit_never_matches(vcd):
    assert spans(search(vcd, 'bus=b1????????')) == []


# --- inequality -------------------------------------------------------------

def test_not_equal_ignores_x_under_dont_care(vcd):
    # At 40ns the low nibble is x but bit 4 (cared) is a known 1 -> equal,
    # so != fails there; elsewhere bit 4 is a known 0 -> != holds.
    assert spans(search(vcd, 'bus!=b???1????')) == [(0, 40), (50, 60)]


def test_not_equal_blocked_by_x_in_a_cared_bit(vcd):
    # bit 3 is x at 40ns: unknown is not evidence of difference.
    assert spans(search(vcd, 'bus!=b????1???')) == [(0, 20), (50, 60)]


def test_not_equal_over_wide_mask_agrees_with_plain_literal(vcd):
    # A set bit above the width makes the mask unequal to every value, so `!=`
    # holds wherever the cared in-width bits are known -- exactly what a plain
    # over-wide literal answers. (The bit-3 x at 40ns blocks only the mask with
    # bit 3 cared.)
    assert spans(search(vcd, 'bus!=b1????????')) == [(0, 60)]
    assert spans(search(vcd, 'bus!=b1????1???')) == [(0, 40), (50, 60)]
    assert va._condition_match('1010', '!=', '1????????', None, width=8)
    assert va._condition_match('1010', '!=', '100001010', None, width=8)


def test_condition_match_helper_directly():
    assert va._condition_match('1xxxx', '!=', '???0????', None, width=8)
    assert not va._condition_match('1xxxx', '!=', '????0???', None, width=8)
    assert va._value_matches('1xxxx', '???1????', None, width=8)


# --- parse errors -----------------------------------------------------------

@pytest.mark.parametrize('target, message', [
    ('1??0', 'needs a binary prefix'),
    ('0x?a', 'must use binary form'),
    ('b1?2', "don't-care bit"),
])
def test_malformed_masks_are_rejected(target, message):
    with pytest.raises(va._ValueParseError, match=message):
        va._parse_target_value(target)


def test_mask_against_real_signal_is_rejected(vcd):
    with pytest.raises(va._ConditionParseError, match='bit pattern'):
        search(vcd, 'r=b1?')


def test_mask_parses_to_a_raw_target():
    assert va._parse_target_value('b1??0') == ('1??0', None, None)
    assert va._parse_target_value('0B?1') == ('?1', None, None)


def test_mask_through_the_cli(vcd):
    r = run_cli(['search', str(vcd), '--condition', 'bus=b??????1?'])
    assert r.returncode == 0
    assert 'Found: 1 interval(s)' in r.stdout
