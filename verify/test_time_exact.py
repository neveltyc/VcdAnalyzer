import vcd_analyzer as va


def test_fmt_time_keeps_every_tick_digit():
    # %g kept 6 significant digits: both of these printed as 17.5347ms.
    assert va.fmt_time(17534712, 1e-9) == '17.534712ms'
    assert va.fmt_time(17534713, 1e-9) == '17.534713ms'
    assert va.fmt_time(17534700, 1e-9) == '17.5347ms'
    assert va.fmt_time(5, 1e-9) == '5ns'
    assert va.fmt_time(1500, 1e-12) == '1.5ns'
    assert va.fmt_time(10 ** 18, 1e-9) == '1000000000s'


def test_fmt_time_non_integral_timescale_falls_back():
    assert va.fmt_time(3, 1.5e-16) == '0.45fs'


def test_parse_time_exact_beyond_float_precision():
    # 2**53 + 1 ticks survive a unit conversion without float rounding.
    assert va.parse_time('9007199254740993ps', 1e-12) == 9007199254740993
    assert va.parse_time('615.329s', 1e-13) == 6153290000000000


def test_parse_time_warns_when_rounding_to_ticks(capsys):
    va._warned.clear()
    assert va.parse_time('15ps', 1e-10) == 0
    assert 'not a whole number of timescale ticks' in capsys.readouterr().err
    assert va.parse_time('17.55us', 1e-12) == 17550000
    assert capsys.readouterr().err == ''
