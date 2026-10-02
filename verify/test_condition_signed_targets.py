"""Negative condition targets and over-wide 4-state targets.

Before this fix every target starting with '-' was rejected, so a real signal
carrying a negative value (iverilog dumps `r-1.5`) could be seen by snapshot
but not searched, and a signed integer/reg could only be found by hand-folding
its value into the unsigned two's-complement number. And a 4-state target
spelled with more leading zeros than the signal width (`b00000001xxxx` on an
8-bit bus) returned a confident empty result instead of matching.

The fixture mirrors what iverilog 13 writes for the corresponding RTL:
`real`, `integer` (= -1 as 32 ones), `reg signed [7:0]` (declared as plain
`reg`; VCD records no signedness), and a compressed x-vector `b1xxxx`.
"""
import contextlib
import io

import pytest

import vcd_analyzer as va
from conftest import load_json_stdout, minimal_vcd, ns, write_vcd


DECLS = ('$var real 1 ! r_val $end\n'
         '$var integer 32 " cnt $end\n'
         '$var reg 8 # sbyte $end\n'
         '$var reg 8 $ bus $end\n'
         '$var wire 1 % bit $end\n')
DATA = ('#0\nr0 !\nb0 "\nb0 #\nb0 $\n0%\n'
        '#10\nr-1.5 !\nb11111111111111111111111111111111 "\nb11111011 #\n1%\n'
        '#20\nb1xxxx $\n'
        '#30\nr-2e-3 !\nb10000000 #\n'
        '#40\nr0 !\n')


@pytest.fixture
def vcd(tmp_path):
    return write_vcd(tmp_path, minimal_vcd(DECLS, DATA))


def search(vcd_path, *conditions):
    v = va.VCDParser(str(vcd_path))
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        va.cmd_search(v, ns(json=True, condition=list(conditions),
                            begin='0ns', end='50ns'))
    return load_json_stdout(buf.getvalue())


def spans(res):
    return [(r['begin_ticks'], r['end_ticks']) for r in res['intervals']]


# --- negative reals ---------------------------------------------------------

def test_negative_real_target_matches(vcd):
    assert spans(search(vcd, 'r_val=-1.5')) == [(10, 30)]


def test_negative_real_exponent_target_matches(vcd):
    assert spans(search(vcd, 'r_val=-2e-3')) == [(30, 40)]


def test_negative_integer_target_on_real_compares_numerically(vcd):
    # -1 on a real signal is the number -1.0, never a two's-complement pattern.
    assert spans(search(vcd, 'r_val=-1')) == []


def test_negative_real_against_logic_signal_is_rejected(vcd):
    with pytest.raises(va._ConditionParseError, match='real number'):
        search(vcd, 'cnt=-1.5')


# --- negative integers: two's complement in the declared width --------------

def test_integer_minus_one_equals_all_ones(vcd):
    assert spans(search(vcd, 'cnt=-1')) == spans(search(vcd, 'cnt=4294967295')) == [(10, 50)]


def test_signed_reg_negative_target(vcd):
    # reg signed [7:0] = -5 is dumped as b11111011 with type 'reg'.
    assert spans(search(vcd, 'sbyte=-5')) == [(10, 30)]


def test_signed_range_minimum_is_accepted(vcd):
    assert spans(search(vcd, 'sbyte=-128')) == [(30, 50)]


def test_target_below_signed_range_is_rejected(vcd):
    with pytest.raises(va._ConditionParseError, match=r'-128\.\.127'):
        search(vcd, 'sbyte=-129')


def test_negative_target_not_equal(vcd):
    assert spans(search(vcd, 'sbyte!=-5')) == [(0, 10), (30, 50)]


def test_one_bit_minus_one_is_one(vcd):
    assert spans(search(vcd, 'bit=-1')) == spans(search(vcd, 'bit=1'))


def test_negative_zero_is_zero(vcd):
    assert spans(search(vcd, 'sbyte=-0')) == spans(search(vcd, 'sbyte=0'))


# --- over-wide 4-state targets ----------------------------------------------

def test_redundant_leading_zeros_are_trimmed(vcd):
    expected = [(20, 50)]
    assert spans(search(vcd, 'bus=b0001xxxx')) == expected
    assert spans(search(vcd, 'bus=b00000001xxxx')) == expected


def test_nonzero_bits_above_width_never_match(vcd):
    for target in ('b10000001xxxx', 'bx0001xxxx', 'bz0001xxxx'):
        assert spans(search(vcd, 'bus=' + target)) == []


def test_over_wide_target_is_fitted_once_at_resolve_time(vcd):
    # The trim happens in _fit_target_to_width, so the matcher sees the
    # fitted literal; nonzero excess is left for the matcher to reject.
    v = va.VCDParser(str(vcd))
    (fitted,) = va._resolve_conditions(v, 'bus=b00000001xxxx')
    assert fitted['target_raw'] == '0001xxxx'
    (kept,) = va._resolve_conditions(v, 'bus=b10000001xxxx')
    assert kept['target_raw'] == '10000001xxxx'


# --- numeric spelling: ASCII digits and the VCD real grammar only -----------

@pytest.mark.parametrize('target', [
    '\u00b2', '-\u00b2',        # isdigit() but int() rejects: was a raw traceback
    '\u0661', '-\u0661',        # Arabic-Indic digit: was accepted as 1 / -1
    '1_000', '-1_0', '-1_5.0',  # float() underscores: not a VCD real spelling
    '--1', '-+1', '-', '-0x1', '-b1', '-inf', '-nan',
])
def test_non_vcd_numeric_spellings_are_rejected(target):
    with pytest.raises(va._ValueParseError):
        va._parse_target_value(target)


def test_non_ascii_digit_condition_is_a_clean_cli_error(tmp_path):
    from conftest import run_cli
    p = write_vcd(tmp_path, minimal_vcd(DECLS, DATA))
    r = run_cli(['search', str(p), '--condition', 'cnt=-\u00b2'])
    assert r.returncode != 0
    assert 'Traceback' not in r.stderr
    assert r.stderr.startswith('Error:')
