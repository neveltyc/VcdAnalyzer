# ================================================================
# Part 1: Time base, resource limits and shared tables
# ================================================================


_UNITS = {'fs': 1e-15, 'ps': 1e-12, 'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1.0}
# Exact unit sizes in femtoseconds. Time conversion and display use integer
# femtosecond arithmetic so a tick count is never rounded through a float.
_UNIT_FS = {'fs': 1, 'ps': 10 ** 3, 'ns': 10 ** 6, 'us': 10 ** 9, 'ms': 10 ** 12, 's': 10 ** 15}
_DISPLAY_UNITS = ('fs', 'ps', 'ns', 'us', 'ms', 's')


@lru_cache(maxsize=64)
def _tick_fs(ts_sec):
    """Exact femtoseconds per tick for a float timescale, or None.

    Every timescale the parser produces is an integer multiple of 1 fs, so the
    float is recovered exactly by rounding. A non-integral or non-finite value
    (only reachable through direct API calls) returns None and callers fall
    back to float arithmetic.
    """
    try:
        fs = ts_sec / 1e-15
    except TypeError:
        return None
    if not math.isfinite(fs) or fs < 0.5:
        return None
    n = round(fs)
    if abs(fs - n) > 1e-6 * n:
        return None
    return n


_warned = set()


def _warn(msg, cat=None):
    """Emit one stderr warning per category/message; stdout/JSON stay clean."""
    key = cat if cat is not None else msg
    if key in _warned:
        return
    _warned.add(key)
    try:
        sys.stderr.write('Warning: {}\n'.format(msg))
    except (OSError, ValueError):
        pass


# Resource limits — generous defaults that never trip on real engineering
# files but reject pathological/malicious inputs cleanly.
# Override per-process via environment variables, e.g.:
#   VCD_ANALYZER_MAX_VARS=2000000 vcd_analyzer info big.vcd
def _env_int(name, default):
    """Read a positive integer resource limit from the environment."""
    raw = os.environ.get(name)
    if raw is None or raw == '':
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


MAX_VARS = _env_int('VCD_ANALYZER_MAX_VARS', 1_000_000)
MAX_REASSEMBLE_BITS = _env_int('VCD_ANALYZER_MAX_REASSEMBLE_BITS', 65536)
MAX_TIME_ARG_LEN = 100         # CLI/programmatic time string length cap
MAX_TIME_TICKS = (1 << 63) - 1  # int64 max — keeps downstream arithmetic safe
MAX_FILTER_PATTERN_LEN = 256
MAX_FILTER_WILDCARDS = 16

# Additional header-section caps. Defaults are far above any legitimate
# engineering VCD but cleanly refuse pathological/malicious construction.
#
# Two failure modes are used:
#  - fail-fast (raise _VCDResourceError): for caps whose violation would
#    corrupt data correctness (lost value_changes, lost $var declarations,
#    deep scope that breaks path reconstruction).
#  - silent drop (truncate retained list): for metadata-only caps whose
#    violation only affects the cosmetic output of `info --verbose`. These
#    are noted inline where they apply.
MAX_INT_DIGITS = 100              # any int-from-string in header (width, bit idx, msb/lsb)
MAX_SIGNAL_WIDTH = MAX_REASSEMBLE_BITS  # max bits per single $var declaration
MAX_VALUE_ARG_LEN = MAX_SIGNAL_WIDTH + 2  # target value string, allows b<MAX_SIGNAL_WIDTH bits>
MAX_DECIMAL_VALUE_DIGITS = 100  # avoid Python 3.9 int() CPU DoS on --value decimal
MAX_HEX_VALUE_DIGITS = max(1, (MAX_SIGNAL_WIDTH + 3) // 4)
MAX_HEADER_BODY_TOKENS = 131072   # any $<kw>...$end section body length (metadata-only effect:
                                  # truncates $comment / $date / $version bodies; $var bodies
                                  # are never long enough to be affected in practice)
MAX_COMMENTS = 1024               # number of $comment sections retained (metadata-only)
MAX_SCOPE_DEPTH = 256             # $scope nesting depth (fail-fast: lost scope breaks path)
MAX_INITIAL_TOKENS = 131072       # tokens buffered from same line as $enddefinitions $end
                                  # (fail-fast: these are data tokens, dropping them
                                  # would silently corrupt waveforms)
MAX_DATA_TOKEN_LEN = _env_int('VCD_ANALYZER_MAX_DATA_TOKEN_LEN', 1 << 20)


def _check_token_lengths(tokens):
    if max(map(len, tokens), default=0) > MAX_DATA_TOKEN_LEN:
        raise _VCDResourceError('VCD token exceeds {} characters'.format(MAX_DATA_TOKEN_LEN))


# IEEE 1364-2005 18.2.2 real value_change is 'r' + real_number where
# real_number follows C99 printf("%g") shape: optional sign, integer and/or
# fractional digits, optional exponent. Used to reject garbage tokens like
# 'reset' that start with 'r' but aren't a numeric value_change.
#
# Pattern written to avoid backtracking (no alternation overlap):
#   sign?  ( digits  ( '.' digits? )?  |  '.' digits )  exponent?
# The two top-level alternatives are disjoint (start with digit vs '.'),
# so the engine never has to backtrack between them. Inputs are also
# length-bounded below; real_number tokens in VCD value_changes shouldn't
# exceed reasonable %g output width.
_REAL_RE = re.compile(
    r'^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$'
)
_REAL_MAX_LEN = 64  # Defensive cap: %.16g + sign + exponent fits well under this

# C99 7.19.6.1: %g renders ±inf as 'inf' and NaN as 'nan' 'optionally
# followed by an implementation-defined sequence of characters' — e.g. the
# MSVC CRT emits 'nan(snan)' / 'nan(ind)' — and IEEE 1364's real_number is
# %g output. So these (including the bounded nan(payload) form) are legal
# value_change texts the numeric pattern above cannot match. This companion
# pattern keeps such records in the stream instead of silently dropping a
# legal dump record (the pre-fix behavior lost the event from dump, info's
# time range, and summary counts with no diagnostic). Condition matching:
# _parse_target_value still rejects non-finite targets (nan never compares
# equal and inf has no finite equal), so '=' can never match them; but '!='
# with a finite target DOES match non-finite values (nan/inf compare unequal
# to it) — the same rule as any other non-matching real value.
_REAL_NONFINITE_RE = re.compile(
    r'^[+-]?(?:inf(?:inity)?|nan(?:\([^()\s]+\))?)$', re.IGNORECASE
)

# Fast 4-state validation tables. str.translate() runs entirely in C, so
# "delete every allowed character, then check for an empty remainder" is the
# fastest stdlib test for "are all characters drawn from this set?". This
# replaces per-character all()/any() generator scans on the hot value-change
# path, where they accounted for tens of millions of Python-level iterations.
_DEL_4STATE_LOWER = {ord(c): None for c in '01xz'}     # canonical lowercase
_DEL_MASK_LOWER = {ord(c): None for c in '01xz?'}      # 4-state + don't-care
_DEL_4STATE_CI = {ord(c): None for c in '01xXzZ'}      # raw VCD, case-insensitive

# VCD vector left-extension fill (IEEE 1364 Table 18-1), keyed by the MSB of a
# lowercase 4-state value: x/z extend themselves, 0/1 extend with 0.
_PAD_CHAR = {'0': '0', '1': '0', 'x': 'x', 'z': 'z'}

# Extended VCD port state character → 4-state mapping (IEEE 1364-2005 18.4.3.1).
# Strengths (driver levels 0-7) are not exposed; for RTL debug the 4-state value
# is what matters. Conflict states (d/u/l/h) collapse to their logical level.
_PORT_STATE = {
    # Input (testfixture)
    'D': '0', 'U': '1', 'N': 'x', 'Z': 'z', 'd': '0', 'u': '1',
    # Output (DUT)
    'L': '0', 'H': '1', 'X': 'x', 'T': 'z', 'l': '0', 'h': '1',
    # Unknown direction (both input and output active)
    '0': '0', '1': '1', '?': 'x', 'F': 'z',
    'A': 'x', 'a': 'x', 'B': 'x', 'b': 'x', 'C': 'x', 'c': 'x', 'f': 'z',
}


def _parse_timescale(text):
    """Extract base time unit in seconds from $timescale line.

    IEEE 1364-2005 18.2.3.8 only allows 1, 10, or 100 as the number, but
    we accept any positive integer for lenience. A zero, missing, or
    pathologically long number falls back to 1e-12 (1 ps) — the standard's
    default — to avoid downstream division-by-zero in parse_time and CPU
    DoS from int() on huge digit strings (Python 3.9 is O(n^2)).
    """
    ts = _parse_timescale_strict(text)
    return 1e-12 if ts is None else ts


def _parse_timescale_strict(text):
    """Like _parse_timescale, but None instead of the 1 ps fallback."""
    m = re.search(r'(\d+)\s*(fs|ps|ns|us|ms|s)', text)
    if not m:
        return None
    digits = m.group(1)
    # Length cap matches parse_time's MAX_TIME_ARG_LEN. The standard allows
    # only 1/10/100 (≤3 digits), so anything multi-line absurd is corruption.
    if len(digits) > MAX_TIME_ARG_LEN:
        return None
    n = int(digits)
    if n <= 0:
        return None
    return n * _UNITS[m.group(2)]


class _TimeParseError(ValueError):
    """Raised by parse_time on invalid input; caught in main() for friendly CLI errors."""


class _LimitParseError(ValueError):
    """Raised when --limit is invalid (e.g. negative). Separate from
    _TimeParseError so the two validation failures never share a message
    identity; caught in main() for a friendly CLI error."""


class _FilterParseError(argparse.ArgumentTypeError):
    """Raised when --filter contains an unsafe or unsupported pattern.
    argparse handles this automatically with a friendly message."""


class _ValueParseError(ValueError):
    """Raised when a target value is too large or malformed beyond tolerant matching."""


class _ConditionParseError(ValueError):
    """Raised when search --condition / --show / --changed is invalid."""


class _VCDResourceError(RuntimeError):
    """Raised when a VCD input exceeds configured resource limits.
    Surfaced in main() as a CLI error, no Python traceback."""


def _check_time_range(ticks, original):
    if ticks < 0:
        raise _TimeParseError('time must be non-negative; got {!r}'.format(original))
    if ticks > MAX_TIME_TICKS:
        raise _TimeParseError(
            'time value too large; got {!r}, max ticks is {}'.format(original, MAX_TIME_TICKS))
    return ticks


def _parse_vcd_timestamp_token(tok):
    """Parse a VCD '#<digits>' simulation_time token into an int.

    Returns int on success, None for malformed input (e.g. '#1.5' — digit
    prefix passed the isdigit() pre-check but int() rejects it). The
    None-path preserves the round-7 "tolerant reader" behavior: malformed
    timestamps are silently skipped, the rest of the stream continues.

    Raises _VCDResourceError for inputs that would cause CPU/memory DoS or
    exceed int64. Python 3.11+ imposes a built-in decimal digit limit on
    int(str) (sys.int_max_str_digits, default 4300) as a CPU-DoS countermeasure
    (bpo/GH-95770; no PEP - PEP 678 is the unrelated exception add_note()
    proposal), but we target 3.9 where int(s) is O(n^2) for huge n; even on
    3.11+ that ValueError would otherwise become an unhandled traceback.
    """
    digits = tok[1:]
    if len(digits) > MAX_TIME_ARG_LEN:
        raise _VCDResourceError(
            'VCD timestamp token too long: {} digits (max {}); '
            'file may be corrupt or malicious'.format(len(digits), MAX_TIME_ARG_LEN))
    try:
        v = int(digits)
    except ValueError:
        return None  # tolerated malformed (e.g. '#1.5')
    if v > MAX_TIME_TICKS:
        raise _VCDResourceError(
            'VCD timestamp too large: got {}, max ticks is {}'.format(v, MAX_TIME_TICKS))
    return v


def _safe_int_digits(s):
    """Parse a digit string from VCD header to int with bounded cost.

    Used wherever the header declares an integer in user-controlled
    position: $var width, [msb:lsb] range, [N] bit index. Returns int
    on success, None for empty / malformed / oversized inputs. Never
    raises — caller decides whether to skip the declaration or raise
    _VCDResourceError with richer context.

    Length cap MAX_INT_DIGITS=100 defends against the same Python 3.9
    O(n^2) decimal-int and Python 3.11+ int_max_str_digits ValueError issues
    as _parse_vcd_timestamp_token. 100 digits is far beyond any legitimate
    bit width or index (which fit in 4 digits comfortably).
    """
    if not s or len(s) > MAX_INT_DIGITS:
        return None
    try:
        return int(s)
    except ValueError:
        return None


def parse_time(s, ts_sec):
    """Parse time string with optional unit suffix to internal VCD timestamp.

    VCD timestamps per IEEE 1364-2005 18.2.3.8 are non-negative integers.
    - With unit: any non-negative value, scaled to ticks (e.g. '17.5us', '.5ns')
    - Without unit: must be a non-negative integer tick count

    Bare '10.5' (no unit) is rejected to avoid silent int() truncation;
    use '10.5ns' to specify a fractional time. Whitespace between number
    and unit is NOT allowed ('5 ns' is rejected; standard unit literals
    are written as a single token).

    Hardened against:
    - ZeroDivisionError when ts_sec <= 0 (e.g. malformed $timescale)
    - Overflow / non-finite intermediate values
    - Overlong input strings (CPU DoS)
    - Tick counts exceeding int64
    """
    if s is None:
        return None
    if not isinstance(s, str):
        raise _TimeParseError(
            'time value must be a string; got {}'.format(type(s).__name__))
    if len(s) > MAX_TIME_ARG_LEN:
        raise _TimeParseError(
            'time value too long; max length is {}'.format(MAX_TIME_ARG_LEN))
    stripped = s.strip()
    if not stripped.isascii() or '_' in stripped:
        raise _TimeParseError('invalid time value {!r}'.format(s))
    # Anchored match — no \s* between value and unit ('5 ns' must be rejected).
    m = re.match(r'^([+-]?)(\d+\.\d*|\.\d+|\d+)(fs|ps|ns|us|ms|s)?$', stripped)
    if not m:
        # Fall back to bare integer ('100', '-5'); reject anything else.
        try:
            v = int(stripped)
        except (ValueError, TypeError):
            raise _TimeParseError(
                'invalid time value {!r}; expected integer ticks or value '
                'with fs/ps/ns/us/ms/s suffix'.format(s))
        return _check_time_range(v, s)
    sign, val_str, unit = m.group(1), m.group(2), m.group(3)
    if sign == '-' and val_str.strip('0.') != '':
        # Reject negative non-zero. '-0' / '-0.0' silently treated as 0.
        raise _TimeParseError(
            'time must be non-negative; got {!r}'.format(s))
    if unit is None:
        if '.' in val_str:
            raise _TimeParseError(
                'bare numeric time must be integer ticks; got {!r}. '
                'Use a unit suffix for fractional times, e.g. {}ns'.format(s, val_str))
        return _check_time_range(int(val_str), s)
    if ts_sec <= 0:
        raise _TimeParseError(
            'cannot convert time with unit because VCD $timescale is 0 or invalid')
    tick = _tick_fs(ts_sec)
    if tick is not None:
        # Exact rational conversion: '17.55us' on a 1ps timescale is exactly
        # 17550000 ticks, independent of float representation, and tick counts
        # beyond 2**53 keep every digit.
        exact = Fraction(val_str) * _UNIT_FS[unit] / tick
        ticks = round(exact)
        if exact.denominator != 1:
            _warn('time argument is not a whole number of timescale ticks; '
                  'rounded to nearest tick', cat='time_rounding')
        return _check_time_range(ticks, s)
    try:
        scaled = float(val_str) * _UNITS[unit] / ts_sec
    except (OverflowError, ValueError, ZeroDivisionError):
        raise _TimeParseError('invalid time value {!r}'.format(s))
    if not math.isfinite(scaled):
        raise _TimeParseError('time value {!r} is not finite'.format(s))
    return _check_time_range(int(round(scaled)), s)


def fmt_time(ts, ts_sec):
    """Format internal timestamp to human-readable string.

    Picks the smallest unit u where |scaled| < 1000, preferring natural
    boundaries. E.g. with timescale 1ns, #5 prints as '5ns' not '5000ps';
    #17534700 prints as '17.5347ms'.

    Defensive: non-finite ts or ts_sec produces '?', not 'infs' / 'nans'.
    """
    if ts == 0:
        return '0s'
    # math.isfinite handles int, float, bool. inf/nan slip through arithmetic
    # otherwise and produce garbage like 'infs'.
    try:
        if not (math.isfinite(ts) and math.isfinite(ts_sec)):
            return '?'
    except TypeError:
        return '?'
    if ts_sec <= 0:
        return '?'
    tick = _tick_fs(ts_sec) if isinstance(ts, int) else None
    if tick is not None:
        # Exact decimal rendering: distinct ticks never print identically
        # (%g kept only 6 significant digits, so 17534712ns and 17534713ns
        # both showed as 17.5347ms).
        total = ts * tick
        mag = -total if total < 0 else total
        for u in _DISPLAY_UNITS:
            div = _UNIT_FS[u]
            if mag < 1000 * div or u == 's':
                q, r = divmod(mag, div)
                text = str(q)
                if r:
                    width = len(str(div)) - 1
                    text += '.' + str(r).zfill(width).rstrip('0')
                return ('-' if total < 0 else '') + text + u
    sec = ts * ts_sec
    # u == 's' always matches the bound below, so the loop always returns.
    for u in ('fs', 'ps', 'ns', 'us', 'ms', 's'):
        scaled = sec / _UNITS[u]
        if -1000.0 < scaled < 1000.0 or u == 's':
            return f'{scaled:g}{u}'


