#!/usr/bin/env python3
"""Assemble src/ into the release single files.

Usage:
    python _make.py                 # build vcd_analyzer.py (full) and vcd_analyzer_lite.py
    python _make.py --full          # build vcd_analyzer.py only
    python _make.py --lite          # build vcd_analyzer_lite.py only
    python _make.py --check         # verify both tracked files against src/
    python _make.py --check-native DIR
                                    # verify the libraries embedded in
                                    # vcd_analyzer.py are byte-identical to
                                    # a fresh build in DIR (CI)

The module order matches the Part numbering in the assembled file:

    _preamble.py    shebang, docstring, imports, version
    timebase.py     Part 1:  time units, exact tick math, resource limits,
                             shared 4-state/real/port tables, exceptions
    values.py       Part 2:  value formatting, clamping, filter patterns
    parser.py       Part 3:  VCDParser (header, bit-exploded reassembly,
                             change stream)  (syncs with OpenWaveAnalyzer)
    index.py        Part 4:  FULL build — the .vcidx reader, native/pure
                             builders, usage gate, auto-build, `index`
    index_stub.py   Part 4:  LITE build — keeps 1.5.6 pure-Python behavior;
                             index attempts get a clear "full variant only"
                             error
    output.py       Part 5:  JSON/text output helpers, limits, truncation
    conditions.py   Part 6:  search condition parse/resolve/evaluate and
                             per-timestamp stream grouping
    summary.py      Part 7:  window summary rows
    commands.py     Part 8:  the query commands
    cli.py          Part 9:  argparse wiring and entry point

The full build also carries a GENERATED part just before cli.py that embeds
the native index-builder libraries (see "full variant" below). The lite
build drops the preamble's marked "full variant only" import block.

Each file is concatenated as-is, so the assembled output is a byte-level
exact reproduction of the modules — `--check` (run in CI) fails the build
whenever a release file drifts from src/.

Maintenance rule (enforced by CI): edit src/, never the release files,
then regenerate before committing:

    python _make.py          # rebuild both artifacts (--check verifies)

Without native/dist/ the full build reuses the libraries already embedded in
vcd_analyzer.py, so Python-only changes need no Rust toolchain. After
changing native/, rebuild the libraries (native/build_all.sh, or download
the `native-dist` artifact of the CI `native` job) into native/dist/ first.

The test suite runs in CI on every push (Linux/macOS/Windows, Python
3.8-3.13); running it locally first is optional and recommended for
large changes.

Discipline: only _preamble.py may contain module-level imports — the parts
share one namespace by concatenation, and a stray import would still work
but hides dependencies; --check rejects it.
"""

import ast
import base64
import hashlib
import lzma
import re
import sys
import textwrap
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC_DIR = HERE / 'src'
OUTPUT = HERE / 'vcd_analyzer.py'

# Assembly order — must match the Part sequence.
SHARED_PARTS = [
    '_preamble.py',
    'timebase.py',
    'values.py',
    'parser.py',
]
TAIL_PARTS = [
    'output.py',
    'conditions.py',
    'summary.py',
    'commands.py',
    'cli.py',
]

# Lite variant: 1.5.6 behavior, no index machinery (stub occupies the
# Part-4 slot so commands/CLI assemble unchanged).
MODULE_ORDER = SHARED_PARTS + ['index_stub.py'] + TAIL_PARTS

# Full variant: the real index engine replaces the stub; the generated
# native part is inserted just before cli.py by assemble_full().
FAST_MODULE_ORDER = SHARED_PARTS + ['index.py'] + TAIL_PARTS

_TOP_LEVEL_IMPORT = re.compile(r'^(?:import|from)\s', re.MULTILINE)
# Preamble imports used only by the index engine; the lite build drops them.
_FULL_ONLY_IMPORTS = re.compile(
    r'^# -- full variant only:.*?^# -- end full variant only --\n',
    re.MULTILINE | re.DOTALL)


def check_discipline(text_by_module, order):
    """Only _preamble.py may import at module level (column-0 import/from)."""
    problems = []
    for name in order:
        if name == '_preamble.py':
            continue
        match = _TOP_LEVEL_IMPORT.search(text_by_module[name])
        if match:
            line = text_by_module[name][:match.start()].count('\n') + 1
            problems.append(f'{name}:{line}: module-level import outside _preamble.py')
    return problems


def assemble() -> str:
    return _concat(MODULE_ORDER, lite=True)


def _concat(order, lite=False):
    parts = {}
    for name in order:
        path = SRC_DIR / name
        if not path.exists():
            sys.exit(f'Error: missing module {path}')
        parts[name] = path.read_text(encoding='utf-8')
    if lite:
        parts['_preamble.py'], n = _FULL_ONLY_IMPORTS.subn('', parts['_preamble.py'])
        if n != 1:
            sys.exit('Error: _preamble.py must hold exactly one '
                     '"full variant only" import block')
    problems = check_discipline(parts, order)
    if problems:
        for p in problems:
            print(f'Error: {p}', file=sys.stderr)
        sys.exit(1)
    return ''.join(parts[name] for name in order)


# -- full variant (embedded native part) -------------------------------------
#
# vcd_analyzer.py (full) = the lite assembly's shared parts with the REAL
# index engine, plus a GENERATED part appended before cli.py that embeds
# the native index-builder libraries (lzma + base85) for arm64-linux /
# x86-64-linux / arm64-macos / x86-64-windows and loads them through
# ctypes (C ABI), falling back to the pure-Python builder whenever
# anything is missing. The generated part never lives in src/ (it is
# data, and it needs imports the discipline check forbids).

FULL_OUTPUT = HERE / 'vcd_analyzer.py'
LITE_OUTPUT = HERE / 'vcd_analyzer_lite.py'
NATIVE_DIST = HERE / 'native' / 'dist'
NATIVE_LIBS = (
    ('aarch64-linux', 'aarch64-linux.so', '.so'),
    ('x86_64-linux', 'x86_64-linux.so', '.so'),
    ('aarch64-macos', 'aarch64-macos.dylib', '.dylib'),
    ('x86_64-windows', 'x86_64-windows.dll', '.dll'),
)

_FAST_TEMPLATE = '''# ================================================================
# Fast variant part: embedded native index builder (GENERATED by
# _make.py from native/dist/ — do not edit, not part of src/)
# ================================================================
#
# Compressed (lzma) + base85 copies of the vcdidx cdylib for each shipped
# platform. Linux loads straight from memory (memfd + dlopen on
# /proc/self/fd, no disk); macOS and Windows dlopen by path only, so there
# the library is checksum-verified, atomically extracted once to a fixed
# cache dir and loaded. ANY failure — unsupported platform, read-only
# cache, antivirus, load error — silently falls back to the pure-Python
# builder in Part 4; correctness never depends on this part.

import base64
import ctypes
import hashlib
import lzma
import platform as _platform

_NATIVE_ABI_VERSION = 2
_NATIVE_LIBS = {
__LIBS__
}


def _native_platform_key():
    machine = _platform.machine().lower()
    arch = {'arm64': 'aarch64', 'aarch64': 'aarch64',
             'x86_64': 'x86_64', 'amd64': 'x86_64'}.get(machine)
    if arch is None:
        return None
    if sys.platform == 'darwin':
        return 'aarch64-macos' if arch == 'aarch64' else None
    if sys.platform.startswith('linux'):
        return arch + '-linux'
    if sys.platform == 'win32':
        return 'x86_64-windows' if arch == 'x86_64' else None
    return None


_native_library_cache = {}
_native_keep_open = []  # memfd handles that must outlive the CDLL load


def _load_native_library():
    key = _native_platform_key()
    if key is None or key not in _NATIVE_LIBS:
        return None
    if key in _native_library_cache:
        return _native_library_cache[key]
    info = _NATIVE_LIBS[key]
    raw = None

    def _verified_bytes():
        data = lzma.decompress(base64.b85decode(''.join(info['data'].split())))
        if (hashlib.sha256(data).hexdigest() != info['sha256']
                or len(data) != info['size']):
            return None
        return data

    try:
        lib = None
        if sys.platform.startswith('linux'):
            # memfd + dlopen: the library never touches the filesystem.
            try:
                blob = _verified_bytes()
                if blob is not None:
                    fd = os.memfd_create('vcdidx', 0)
                    os.write(fd, blob)
                    os.lseek(fd, 0, os.SEEK_SET)
                    lib = ctypes.CDLL('/proc/self/fd/{}'.format(fd))
                    _native_keep_open.append(fd)  # mapping lives with the fd
            except (AttributeError, OSError, ValueError):
                lib = None  # fall through to the disk path
        if lib is None:
            if sys.platform == 'win32':
                base = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~')
                cache_dir = os.path.join(base, 'vcd_analyzer-native')
            else:
                cache_dir = os.path.join(os.path.expanduser('~'), '.cache',
                                         'vcd_analyzer-native')
            target = os.path.join(cache_dir, 'vcdidx-{}-{}{}'.format(
                _NATIVE_ABI_VERSION, info['sha256'][:16], info['ext']))
            if not os.path.exists(target):
                raw = _verified_bytes()
                if raw is None:
                    return None
                os.makedirs(cache_dir, exist_ok=True, mode=0o700)
                fd, tmp = tempfile.mkstemp(dir=cache_dir, suffix='.part')
                try:
                    with os.fdopen(fd, 'wb') as out:
                        out.write(raw)
                    os.replace(tmp, target)
                except BaseException:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                    raise
            else:
                # Re-verify a pre-existing cache file before loading it:
                # the extraction path checks, the cached path must too.
                with open(target, 'rb') as f:
                    if hashlib.sha256(f.read()).hexdigest() != info['sha256']:
                        return None
            lib = ctypes.CDLL(target)
        if lib.vcdidx_abi_version() != _NATIVE_ABI_VERSION:
            return None
        lib.vcdidx_abi_build.restype = ctypes.c_int
        lib.vcdidx_abi_build.argtypes = [
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
        _native_library_cache[key] = lib
        return lib
    except (OSError, ValueError, AttributeError, ImportError):
        return None


def _NATIVE_INDEX_BUILD(path, sidecar, block_bytes, budget_bytes=0):
    """Build the sidecar natively. None when no usable library (the caller
    falls back to the pure-Python builder); ValueError for fatal build
    errors (non-monotonic timestamps, changed source) so they surface
    instead of being rebuilt slowly and reported late."""
    lib = _load_native_library()
    if lib is None:
        return None
    started = time.perf_counter()
    parser = VCDParser(str(path))
    symbols = raw_symbols(parser)
    manifest = ('data_start {}\\nblock_bytes {}\\nbudget_bytes {}\\nmax_token_len {}\\n'
                'symbols {}\\n{}\\n').format(
        data_start(path), block_bytes, budget_bytes, MAX_DATA_TOKEN_LEN,
        len(symbols), '\\n'.join(symbols)).encode('utf-8')
    err = ctypes.create_string_buffer(512)
    stats_buf = ctypes.create_string_buffer(8192)
    rc = lib.vcdidx_abi_build(manifest, len(manifest), str(path).encode('utf-8'),
                              str(sidecar).encode('utf-8'), err, 512,
                              stats_buf, 8192)
    if rc != 0:
        raise ValueError(err.value.decode('utf-8', 'replace')
                         or 'native builder failed')
    stats = json.loads(stats_buf.value.decode('utf-8'))
    stats['build_s'] = time.perf_counter() - started
    stats['directory_bytes'] = (56 + 32 * stats['blocks']
                                + 16 * stats['raw_symbols'])
    return stats
'''


def fast_builder_ready() -> bool:
    return all((NATIVE_DIST / f).exists() for _, f, _e in NATIVE_LIBS)


def _lib_entries_from_dist():
    entries = []
    for key, filename, ext in NATIVE_LIBS:
        path = NATIVE_DIST / filename
        if not path.exists():
            sys.exit('Error: missing {} — build the native libraries first:\n'
                     '  native/build_all.sh'.format(path))
        raw = path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        blob = base64.b85encode(lzma.compress(raw, preset=9 | lzma.PRESET_EXTREME)).decode('ascii')
        wrapped = textwrap.wrap(blob, 116)
        data = "'''\n" + '\n'.join(wrapped) + "'''"
        entries.append(
            "    '{}': {{'ext': '{}', 'sha256': '{}', 'size': {}, 'data': {}}},".format(
                key, ext, sha, len(raw), data))
    return '\n'.join(entries)


_LIBS_BLOCK = re.compile(r'^_NATIVE_LIBS = \{\n(.*?)\n\}\n', re.MULTILINE | re.DOTALL)


def _lib_entries_from_release(text):
    """The library entries embedded in an assembled full file, verbatim."""
    match = _LIBS_BLOCK.search(text)
    return match.group(1) if match else None


def _decode_entries(entries_text):
    """{key: raw bytes} for embedded entries, verified against their own
    recorded sha256 and size; raises ValueError on any mismatch."""
    libs = ast.literal_eval('{\n' + entries_text + '\n}')
    keys = [key for key, _f, _e in NATIVE_LIBS]
    if sorted(libs) != sorted(keys):
        raise ValueError('embedded platforms {} != {}'.format(sorted(libs), sorted(keys)))
    out = {}
    for key, info in libs.items():
        raw = lzma.decompress(base64.b85decode(''.join(info['data'].split())))
        if hashlib.sha256(raw).hexdigest() != info['sha256'] or len(raw) != info['size']:
            raise ValueError('{}: embedded library does not match its sha256/size'.format(key))
        out[key] = raw
    return out


def generate_fast_part(entries_text) -> str:
    return _FAST_TEMPLATE.replace('__LIBS__', entries_text)


def full_head_tail():
    head = _concat(FAST_MODULE_ORDER[:-1])
    tail = (SRC_DIR / FAST_MODULE_ORDER[-1]).read_text(encoding='utf-8')
    return head, tail


def assemble_full(entries_text) -> str:
    """head + generated native part + cli.py. The native part MUST precede
    cli.py: the __main__ block runs main() at import-completion, and
    main() -> index needs _NATIVE_INDEX_BUILD to already exist."""
    head, tail = full_head_tail()
    return head + generate_fast_part(entries_text) + tail


def _report(name, ok, detail=''):
    print(('OK: ' if ok else 'MISMATCH: ') + name + ((' ' + detail) if detail else ''))
    return 0 if ok else 1


def _read_release(path):
    return path.read_text(encoding='utf-8').replace('\r\n', '\n')


def check_full() -> int:
    """Byte-exact: the full file must equal a fresh assembly of src/ around
    its own embedded libraries, and every library must match its recorded
    sha256. (Whether those libraries match the Rust sources is checked by
    --check-native against a fresh build.)"""
    if not FULL_OUTPUT.exists():
        return _report(FULL_OUTPUT.name, False, 'missing; run: python _make.py --full')
    current = _read_release(FULL_OUTPUT)
    entries = _lib_entries_from_release(current)
    if entries is None:
        return _report(FULL_OUTPUT.name, False, 'no embedded native part; rerun _make.py --full')
    try:
        _decode_entries(entries)
    except (ValueError, lzma.LZMAError, SyntaxError, KeyError, TypeError) as error:
        return _report(FULL_OUTPUT.name, False, 'corrupt native part: {}'.format(error))
    same = current == assemble_full(entries)
    return _report(FULL_OUTPUT.name, same, '' if same else 'differs from src/; rerun _make.py')


def check_native(dist) -> int:
    """Every embedded library must be byte-identical to the build in dist."""
    entries = _lib_entries_from_release(_read_release(FULL_OUTPUT))
    embedded = _decode_entries(entries)
    failures = 0
    for key, filename, _ext in NATIVE_LIBS:
        path = Path(dist) / filename
        if not path.exists():
            failures += _report(filename, False, 'missing from {}'.format(dist))
            continue
        built = hashlib.sha256(path.read_bytes()).hexdigest()
        ship = hashlib.sha256(embedded[key]).hexdigest()
        failures += _report(filename, built == ship, '' if built == ship else
                            'embedded {} != fresh build {}; rebuild native/dist and '
                            'rerun _make.py --full'.format(ship[:16], built[:16]))
    return failures


def main():
    check_mode = '--check' in sys.argv
    full_mode = '--full' in sys.argv
    lite_mode = '--lite' in sys.argv

    if '--check-native' in sys.argv:
        position = sys.argv.index('--check-native') + 1
        if position >= len(sys.argv):
            sys.exit('Error: --check-native needs the directory of a fresh build')
        sys.exit(1 if check_native(sys.argv[position]) else 0)

    if check_mode:
        failures = 0
        assembled = assemble()
        if LITE_OUTPUT.exists():
            same = _read_release(LITE_OUTPUT) == assembled.replace('\r\n', '\n')
            failures += _report(LITE_OUTPUT.name, same,
                                '' if same else 'differs from src/; rerun _make.py')
        else:
            failures += _report(LITE_OUTPUT.name, False, 'missing; run: python _make.py --lite')
        failures += check_full()
        sys.exit(1 if failures else 0)

    outputs = []
    if lite_mode or not full_mode:
        outputs.append((LITE_OUTPUT, assemble()))
    if full_mode or not lite_mode:
        if fast_builder_ready():
            entries = _lib_entries_from_dist()
        else:
            entries = (_lib_entries_from_release(_read_release(FULL_OUTPUT))
                       if FULL_OUTPUT.exists() else None)
            if entries is None:
                sys.exit('Error: native/dist/ libraries missing and no embedded '
                         'copy to reuse — run native/build_all.sh')
            _decode_entries(entries)
            print('note: native/dist/ absent; reusing the libraries embedded '
                  'in {}'.format(FULL_OUTPUT.name))
        outputs.append((FULL_OUTPUT, assemble_full(entries)))
    for output, assembled in outputs:
        output.write_text(assembled, encoding='utf-8', newline='\n')
        print(f'Assembled {output.name}: {assembled.count(chr(10))} lines, '
              f'{len(assembled.encode()) / 1024:.0f} KB')


if __name__ == '__main__':
    main()
