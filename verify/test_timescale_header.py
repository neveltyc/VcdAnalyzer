import vcd_analyzer as va
from conftest import run_cli

BODY = ('$scope module tb $end\n$var wire 1 ! a $end\n$upscope $end\n'
        '$enddefinitions $end\n#0\n0!\n#10\n1!\n')


def test_utf8_bom_does_not_hide_timescale(tmp_path):
    p = tmp_path / 'bom.vcd'
    p.write_bytes(b'\xef\xbb\xbf' + ('$timescale 1ns $end\n' + BODY).encode())
    v = va.VCDParser(str(p))
    assert v.ts_sec == 1e-9 and v.timescale_warning is None
    assert v.scan_time_range() == (0, 10)
    assert [e[0] for e in v.iter_events()] == [0, 10]


def test_missing_timescale_warns_on_stderr(tmp_path):
    p = tmp_path / 'nots.vcd'
    p.write_text(BODY)
    r = run_cli(['info', p, '--json'])
    assert r.returncode == 0
    assert 'no $timescale declaration; assuming 1ps' in r.stderr
    assert r.stdout.lstrip().startswith('{')


def test_unparseable_timescale_warns(tmp_path):
    p = tmp_path / 'bad.vcd'
    p.write_text('$timescale 0ns $end\n' + BODY)
    v = va.VCDParser(str(p))
    assert v.ts_sec == 1e-12
    assert 'cannot parse' in v.timescale_warning


def test_valid_timescale_is_silent(tmp_path):
    p = tmp_path / 'ok.vcd'
    p.write_text('$timescale 10 ps $end\n' + BODY)
    r = run_cli(['info', p])
    assert r.returncode == 0 and r.stderr == ''
