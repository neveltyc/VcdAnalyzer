from types import SimpleNamespace
from pathlib import Path
import json
import subprocess
import sys

SCRIPT = Path(__file__).resolve().parent.parent / 'vcd_analyzer.py'


def write_vcd(tmp_path, text, name='t.vcd'):
    p = tmp_path / name
    p.write_text(text)
    return p


def minimal_vcd(decls, data, scope='tb', timescale='1ns'):
    return f"$timescale {timescale} $end\n$scope module {scope} $end\n" + decls + "$upscope $end\n$enddefinitions $end\n" + data


def ns(**kwargs):
    defaults = dict(json=False, verbose=False, limit=None, filter=None, begin=None, end=None, at=None,
                    condition=None, show=None)
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def run_cli(args, timeout=20):
    return subprocess.run([sys.executable, '-S', str(SCRIPT)] + list(map(str, args)),
                          text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout)


# run_cli_patched prelude: every index build fails, as a real one could.
FAIL_BUILD = ('def _fail(*args, **kwargs):\n'
              '    raise ValueError("simulated index failure")\n'
              'va.build_index_best = _fail')


def run_cli_patched(args, prelude, timeout=20, env=None):
    """run_cli with module globals patched first: `prelude` runs with the
    release module bound to `va` (e.g. 'va.NATIVE_PARALLEL_MIN = 1').
    Tuning constants and test seams live in code, not in the environment.
    The program is passed as one exec() line, so no raw newline reaches the
    command line (Windows quoting)."""
    program = ('import sys\nsys.argv = sys.argv[1:]\nsys.path.insert(0, {!r})\n'
               'import vcd_analyzer as va\n{}\nva.main()\n').format(str(SCRIPT.parent), prelude)
    code = 'exec({!r})'.format(program)
    return subprocess.run([sys.executable, '-S', '-c', code, str(SCRIPT)]
                          + list(map(str, args)), text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=timeout, env=env)


def load_json_stdout(text):
    return json.loads(text.strip())

