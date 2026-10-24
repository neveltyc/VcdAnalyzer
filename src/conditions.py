# ================================================================
# Part 6: Condition system and stream grouping
# ================================================================

def _parse_target_value(text):
    """Parse search/condition target once with bounded cost.

    Returns (target_raw, target_int, target_real):

      - Numeric targets (decimal, 0x..., 0b..., b...) get target_int and are
        matched only by numeric equality.
      - 4-state binary literals with x/z keep a raw bit-string target. Explicit
        binary prefixes are stripped because VCD stores vector values as
        ``1x0`` internally, not ``b1x0``.
      - A binary literal may mark don't-care bits with '?' (b?????1??), as in
        a Verilog casez item. It keeps a raw mask target; '?' needs the b/0b
        prefix, so a bare '1??0' is rejected rather than guessed at.
      - A bare number carrying a fraction or exponent (3.14, 1e-9) is a
        target_real, matched only against real/realtime signals.

    A negative decimal integer (-1) keeps its sign in target_int: VCD vector
    text is an unsigned bit string, so the target is mapped to two's
    complement at resolve time, once the signal width is known. A negative
    number with a fraction or exponent (-1.5) is a target_real. Invalid hex
    is rejected rather than silently producing no matches, and x/z literals
    should be written in binary form (e.g. b1x0z).

    A bare target that is none of the above is REJECTED rather than kept as an
    opaque literal that could only ever compare unequal. The tool has no
    in-string boolean syntax, so `--condition "a=1 OR b=1"` parses as a single
    term whose target is the text `1 or b=1`; accepting it produced a
    plausible-looking "no match" instead of an error. OR is spelled by
    repeating --condition.
    """
    if text is None:
        raise _ValueParseError('target value must not be empty')
    raw = str(text).lower().strip()
    if not raw:
        raise _ValueParseError('target value must not be empty')
    if len(raw) > MAX_VALUE_ARG_LEN:
        raise _ValueParseError(
            'target value too long; max length is {}'.format(MAX_VALUE_ARG_LEN))

    if raw.startswith('-'):
        # A negative decimal integer keeps its sign in target_int; it is mapped
        # to the signal's two's-complement bit pattern at resolve time, once
        # the width is known (see _fit_target_to_width). A negative number
        # with a fraction or exponent is a real target, like its positive form.
        num = _parse_bare_number(raw[1:])
        if num is not None:
            target_int, target_real = num
            if target_int is not None:
                return raw, -target_int, None
            return raw, None, -target_real
        raise _ValueParseError(
            'invalid negative target {!r}; only negative decimal integers (-5) '
            'and real numbers (-1.5) are supported'.format(text))

    if raw.startswith('0x'):
        body = raw[2:]
        if not body:
            raise _ValueParseError('hex target must contain at least one digit')
        if len(body) > MAX_HEX_VALUE_DIGITS:
            raise _ValueParseError(
                'hex target too wide; max hex digits is {}'.format(MAX_HEX_VALUE_DIGITS))
        try:
            return raw, int(raw, 16), None
        except ValueError:
            raise _ValueParseError(
                'invalid hex target {!r}; x/z and ? literals must use binary form '
                'like b1x0z or b1??0'.format(text))

    if raw.startswith('0b') or raw.startswith('b'):
        body = raw[2:] if raw.startswith('0b') else raw[1:]
        if not body:
            raise _ValueParseError('binary target must contain at least one bit')
        if len(body) > MAX_SIGNAL_WIDTH:
            raise _ValueParseError(
                'binary target too wide; max bits is {}'.format(MAX_SIGNAL_WIDTH))
        try:
            return body, int(body, 2), None
        except ValueError:
            if _is_mask_bits(body):
                return body, None, None
            raise _ValueParseError(
                "invalid binary target {!r}; expected only 0/1/x/z, or ? for a "
                "don't-care bit".format(text))

    # Bare target, in order: decimal integer, 4-state literal, real number.
    # Anything else is a parse error -- see the docstring on why an opaque
    # literal fallback is worse than saying so.
    if raw.startswith('+'):
        raise _ValueParseError(
            "a leading '+' is not supported; write the value without it")
    num = _parse_bare_number(raw)
    if num is not None:
        return (raw,) + num
    if len(raw) > MAX_SIGNAL_WIDTH:
        raise _ValueParseError(
            'literal target too wide; max characters is {}'.format(MAX_SIGNAL_WIDTH))
    if _is_4state_bits(raw):
        return raw, None, None
    if _is_mask_bits(raw):
        raise _ValueParseError(
            "don't-care target {!r} needs a binary prefix, e.g. b{}".format(text, raw))
    raise _ValueParseError(
        'invalid target {!r}; expected a decimal (5), hex (0xff), binary (b1010), '
        '4-state literal (1x0z), or real number (3.14). Note there is no in-string '
        'boolean syntax: repeat --condition to OR clauses'.format(text))


def _parse_bare_number(text):
    """Classify an unsigned bare number as (target_int, None) or (None, target_real).

    Returns None when text is not a number. Only ASCII is accepted:
    str.isdigit() also admits a superscript two, which int() then rejects
    (a raw traceback), and both float() and _REAL_RE's \\d admit other
    scripts' digits; float() also admits '1_000'. None of these is a spelling
    a VCD value could carry. A real target must match _REAL_RE, the grammar
    the parser applies to dumped real values, and be finite: a VCD real may
    legally be dumped as nan/inf, but neither is a useful equality target
    (nan never compares equal). The caller handles any sign.
    """
    if not text.isascii():
        return None
    if text.isdigit():
        if len(text) > MAX_DECIMAL_VALUE_DIGITS:
            raise _ValueParseError(
                'decimal target too long; max digits is {}'.format(MAX_DECIMAL_VALUE_DIGITS))
        return int(text), None
    # A number carrying a fraction or an exponent targets a real/realtime
    # signal. The sign is the caller's: '--1' must not parse as +1.
    if (text[:1] not in ('+', '-') and len(text) <= MAX_DECIMAL_VALUE_DIGITS + 32
            and _REAL_RE.match(text)):
        fval = float(text)
        if math.isfinite(fval):
            return None, fval
    return None


def _is_4state_bits(text):
    return bool(text) and not text.translate(_DEL_4STATE_LOWER)


def _is_mask_bits(text):
    """True for a 4-state bit string that may also hold '?' don't-care bits."""
    return bool(text) and not text.translate(_DEL_MASK_LOWER)


def _left_extend_bits(bits, width):
    """Apply VCD vector left-extension to a 4-state bit string.

    When a dumped vector is shorter than its declared width, IEEE VCD
    semantics extend the MSB leftward: x extends with x, z with z, and
    0/1 with 0. Use the same rule for user 4-state targets so a condition
    such as data=b1x0 can match an 8-bit stored value 000001x0 without
    asking the Agent to spell out every leading zero.
    """
    if width is None or len(bits) >= width:
        return bits
    msb = bits[0]
    pad = msb if msb in ('x', 'z') else '0'
    return pad * (width - len(bits)) + bits


@lru_cache(maxsize=256)
def _mask_plan(mask, width):
    """Cared bits of a mask laid out over `width`: ((lsb_offset, bit), ...).

    The mask is left-extended to the width by the VCD rule first (a '?' or 0/1
    MSB pads with '0', an x/z MSB with itself), so b1?? on 8 bits still requires
    the top five bits to be 0 -- write every bit, e.g. b?????1??, to leave them
    free. Bits a mask places above the width stay in the plan; the value has no
    such bit, which reads as 0 (_mask_cared_bits). A condition's mask and width
    are fixed once resolved, so the layout is cached rather than rebuilt on
    every evaluation.
    """
    m = _left_extend_bits(mask, width)
    return tuple((off, b) for off, b in enumerate(reversed(m)) if b != '?')


def _mask_cared_bits(value, mask, width):
    """Pair a value's bits with a mask's cared (non-'?') bits.

    A plain 4-state literal is a mask with no '?', so every logic bit-pattern
    comparison -- equality and the `!=` unknown rule -- goes through here.
    Returns [(value_bit, mask_bit), ...], or None when the value is not a
    4-state bit string. A value bit above its declared width does not exist and
    reads as 0, so an over-wide mask with a 1/x/z there (left in place by
    _fit_target_to_width) can never be equal, and `!=` holds once the cared
    bits are known -- the same answer the excess-bit rule always gave.
    """
    if not _is_4state_bits(value):
        return None
    v = _left_extend_bits(value, width)
    n = len(v)
    return [(v[n - 1 - off] if off < n else '0', b)
            for off, b in _mask_plan(mask, width)]


def _real_target_number(target_int, target_real):
    """Numeric value of a target for real/realtime comparison, or None.

    A real target carries its float directly; a decimal/hex/binary target is
    an exact integer that is converted on demand, so `dac=100` asks the same
    question as `dac=100.0`. A bus-width integer can exceed the float range,
    which is not an error -- it simply cannot equal any finite real.
    """
    if target_real is not None:
        return target_real
    if target_int is not None:
        try:
            return float(target_int)
        except OverflowError:
            return None
    return None


def _value_matches(value, target_raw, target_int, width=None, kind=None,
                   target_real=None):
    """Match a recorded value against a parsed search target.

    The recorded value is classified by the signal's DECLARED kind, never by
    sniffing its characters. A real signal carries the simulator's %g text as
    its value, so a real 100.0 renders as "100"; read as a bit string that is
    binary 100 == 4, which made `dac=4` match spuriously and `dac=100` miss.

    kind 'real'/'realtime' therefore compares numerically as floats and never
    as bits. kind 'event' has no level at all and never matches (level terms
    on event variables are rejected at resolve time; this is the belt).

    For logic signals (kind 'vector'/'scalar', or None for callers that do not
    classify):

    - Numeric targets (decimal/hex/binary without x/z) match only by numeric
      equality, avoiding the decimal/binary collision where target 10 would
      otherwise raw-match a 2-bit value "10".
    - Non-numeric 4-state targets (for example b1x0 -> raw "1x0") match as bit
      patterns. If the signal width is known, both the dumped value and the
      target are left-extended to that width using VCD rules before
      comparison. This preserves exact x/z semantics while avoiding the need
      to write every leading zero for wide buses (redundant leading zeros
      beyond the width are trimmed once at resolve time, by
      _fit_target_to_width).
    - A don't-care mask (b?????1??) compares only its non-'?' bits; a plain
      4-state literal is the same comparison with every bit cared
      (_mask_cared_bits).
    - Without a known width, or for a target that is not a bit string, the
      comparison falls back to exact string equality.
    """
    if kind == 'event':
        return False
    if kind == 'real':
        target_num = _real_target_number(target_int, target_real)
        if target_num is None:
            return False
        try:
            return float(value) == target_num
        except (TypeError, ValueError):
            return False
    if target_real is not None:
        # A real-number target against a logic signal (rejected at resolve
        # time; this is the belt for direct callers).
        return False
    if target_int is not None:
        iv = val_to_int(value)
        return iv is not None and iv == target_int
    if width is not None and _is_mask_bits(target_raw):
        cared = _mask_cared_bits(value, target_raw, width)
        return cared is not None and all(v == t for v, t in cared)
    return value == target_raw


_COND_RE = re.compile(r'^\s*(.+?)\s*(==|=|!=)\s*(.+?)\s*$')


def _has_unknown(value, kind=None):
    """True when a VCD value is unknown/ambiguous for negative predicates.

    A real signal's value is decimal text, so a literal 'x'/'z' in it (as in
    the %g rendering of a hex-ish string, or 'nan') is not a 4-state unknown;
    only logic values can be unknown in that sense.
    """
    if value is None:
        return True
    if kind == 'real':
        return False
    return 'x' in value or 'z' in value


def _condition_match(value, op, target_raw, target_int, width=None, kind=None,
                     target_real=None):
    """Evaluate one resolved condition against a raw VCD value.

    Equality reuses the kind-aware value matcher, so real signals compare
    numerically, numeric targets on logic signals compare numerically, and
    mixed x/z literals compare as 4-state bit patterns, width-aware when the
    signal width is available.

    Inequality is deliberately stricter than `not _value_matches(...)`:
    x/z/undef do NOT satisfy `!=`. In RTL debug, unknown is not evidence that
    a signal is definitely different from a value. Users who want unknowns
    should ask for them explicitly, e.g. `valid=x`. Against a don't-care mask
    only the cared bits count: an x under a '?' does not block `!=`.
    """
    if value is None:
        return False
    if op in ('=', '=='):
        return _value_matches(value, target_raw, target_int, width, kind, target_real)
    if op == '!=':
        if (kind != 'real' and width is not None and target_int is None
                and target_real is None and _is_mask_bits(target_raw)):
            # Bit-pattern target (a plain 4-state literal is a mask with no
            # '?'): a don't-care bit's value is not evidence either way, so
            # only the cared bits can make `!=` unknown.
            cared = _mask_cared_bits(value, target_raw, width)
            if cared is None or any(v in 'xz' for v, _t in cared):
                return False
            return any(v != t for v, t in cared)
        if _has_unknown(value, kind):
            return False
        return not _value_matches(value, target_raw, target_int, width, kind, target_real)
    raise AssertionError('unsupported condition operator {}'.format(op))


_CHANGED_PREFIX = 'changed('


def _parse_changed_term(item):
    """Recognize the `changed(SIG)` edge-predicate form.

    Any term starting with `changed(` (case-insensitive) is claimed by this
    syntax. A bare term with no operator was never valid before, so no working
    condition changes meaning; the one shadowed spelling is a level term on an
    escaped identifier that itself begins with `changed(`, which stays
    reachable through a scope-qualified pattern (`tb.changed(a)=1` does not
    start with the prefix).

    Returns None when the term does not start with the prefix; malformed
    `changed(...` shapes get targeted errors rather than the generic one.
    """
    if item[:len(_CHANGED_PREFIX)].lower() != _CHANGED_PREFIX:
        return None
    body = item[len(_CHANGED_PREFIX):]
    if body.endswith(')'):
        inner = body[:-1].strip()
        if not inner:
            raise _ConditionParseError(
                'changed() requires a signal, e.g. changed(req)')
        return {'kind': 'changed', 'pattern': inner, 'original': item}
    if ')' in body:
        # e.g. `changed(req)=1` -- trailing text after the closing paren.
        raise _ConditionParseError(
            'invalid term {!r}: changed(SIG) is a predicate and takes no comparison'.format(item))
    # No closing paren: a plain missing ')', or `changed(a,b)` cut apart by the
    # AND comma before this function ever saw it.
    raise _ConditionParseError(
        "invalid term {!r}: unclosed changed( -- missing ')'? note changed() takes "
        'exactly one signal: a comma inside the parens is read as an AND separator, '
        'so "both changed" is changed(a),changed(b)'.format(item))


def _parse_conditions(text):
    """Parse one comma-separated AND clause into unresolved condition dicts.

    A term is either a level comparison (`SIG=VAL`, `SIG==VAL`, `SIG!=VAL`) or
    the edge predicate `changed(SIG)`, which is true at exactly the ticks where
    SIG transitions. Each dict carries a 'kind' of 'level' or 'changed'.
    """
    if text is None or not str(text).strip():
        raise _ConditionParseError('search requires --condition')
    conditions = []
    for item in str(text).split(','):
        item = item.strip()
        if not item:
            continue
        changed = _parse_changed_term(item)
        if changed is not None:
            conditions.append(changed)
            continue
        m = _COND_RE.match(item)
        if not m:
            raise _ConditionParseError(
                'invalid condition {!r}; expected SIG=VAL, SIG==VAL, SIG!=VAL, '
                'or changed(SIG)'.format(item))
        sig_pat = m.group(1).strip()
        op = m.group(2)
        val_text = m.group(3).strip()
        if not sig_pat or not val_text:
            raise _ConditionParseError(
                'invalid empty signal/value in condition {!r}'.format(item))
        target_raw, target_int, target_real = _parse_target_value(val_text)
        conditions.append({
            'kind': 'level',
            'pattern': sig_pat,
            'op': op,
            'target_raw': target_raw,
            'target_int': target_int,
            'target_real': target_real,
            'original': item,
            'value_text': val_text,
        })
    if not conditions:
        raise _ConditionParseError('search requires at least one condition')
    return conditions


def _resolve_one_signal(vcd, pattern, role):
    """Resolve a condition/trigger pattern to exactly one signal id.

    Matching normally follows VCDParser.match(): substring unless '*' or '?'
    is present. For condition/trigger positions, however, an exact full path
    should win over substring matches. Otherwise a precise path like
    'tb.u.rd_valid' would be rejected merely because 'tb.u.rd_valid0' exists.
    """
    pat = str(pattern).strip()
    pl = pat.lower()
    exact = set()
    if '*' not in pat and '?' not in pat:
        for sid, info in vcd.signals.items():
            for path in info['aliases']:
                if path.lower() == pl:
                    exact.add(sid)
        if len(exact) == 1:
            return next(iter(exact))
        if len(exact) > 1:
            examples = [vcd.signals[s]['path']
                        for s in sorted(exact, key=lambda sid: vcd.signals[sid]['path'])[:5]]
            raise _ConditionParseError(
                '{} pattern {!r} exactly matches {} signals; use list to choose a more specific name, examples: {}'.format(
                    role, pattern, len(exact), ', '.join(examples)))

    sids = vcd.match([pattern])
    if not sids:
        raise _ConditionParseError('{} pattern {!r} matches no signals'.format(role, pattern))
    if len(sids) != 1:
        examples = [vcd.signals[s]['path']
                    for s in sorted(sids, key=lambda sid: vcd.signals[sid]['path'])[:5]]
        extra = ', examples: {}'.format(', '.join(examples)) if examples else ''
        raise _ConditionParseError(
            '{} pattern {!r} matches {} signals; use list to choose a more specific name{}'.format(
                role, pattern, len(sids), extra))
    return next(iter(sids))


def _term_key(c):
    """De-duplication key for one resolved term.

    Keyed on the resolved sid (so alias paths for one signal fold), the
    operator slot ('changed' for the edge predicate, which no comparison
    operator can spell), and the target value AS WRITTEN -- `5` and `0x5` are
    the same number but different spellings and deliberately do not fold, so
    there is no cross-base normalization to get wrong. Shared by the
    within-clause term de-dup and the cross-clause clause_key below, so the
    two can never drift apart.
    """
    if c['kind'] == 'changed':
        return (c['sid'], 'changed', '')
    return (c['sid'], c['op'], '{}:{}'.format(
        c['target_raw'], c['target_int'] is not None or c['target_real'] is not None))


def _check_term_kind(c):
    """Reject a level term the signal's declared kind cannot answer.

    Silence is the wrong answer here: an event variable has no level, and a
    real signal cannot equal a bit pattern, so leaving these to the matcher
    would produce a plausible-looking empty result instead of saying that the
    question does not apply to this signal.
    """
    kind = c['kind_of_signal']
    if kind == 'event':
        raise _ConditionParseError(
            "condition {!r} targets event variable {}, which has no level; "
            'use changed({}) to fire on each trigger'.format(
                c['original'], c['path'], c['path']))
    if kind == 'real':
        if c['target_int'] is None and c['target_real'] is None:
            raise _ConditionParseError(
                'condition {!r} compares real signal {} against a bit pattern; '
                'write a decimal or real number, e.g. {}=3.14'.format(
                    c['original'], c['path'], c['path']))
    elif c['target_real'] is not None:
        raise _ConditionParseError(
            'condition {!r} compares logic signal {} (width {}) against the real '
            'number {}; use a decimal, hex, binary, or 4-state target'.format(
                c['original'], c['path'], c['width'], c['value_text']))


def _fit_target_to_width(c):
    """Fit a logic-signal level target to the signal's declared width, once.

    Runs at resolve time, the first point the width is known, so the matcher
    sees an already-fitted target on every evaluation.

    Negative integer -> two's complement. VCD dumps a signed reg/integer as its raw bit pattern (iverilog writes
    integer -1 as 32 ones) and does not record signedness at all -- a
    `reg signed [7:0]` is declared as plain `reg`. So a negative target is
    read as the declared-width two's-complement pattern on ANY logic signal,
    which is unambiguous given the width: `cnt=-1` on a 32-bit integer is
    `cnt=4294967295`. A value outside the signed range of the width cannot be
    represented and is rejected rather than silently unmatched. Real signals
    keep the signed value and compare numerically.

    Over-wide 4-state literal -> leading zeros trimmed. Excess high bits that
    are all '0' or '?' carry no value (b00000001xxxx on an 8-bit bus is
    0001xxxx; a don't-care bit above the width constrains nothing); a 1/x/z
    above the width is left in place: no value equals it, and `!=` holds once
    the cared bits are known (_mask_cared_bits).
    """
    if c['kind_of_signal'] == 'real':
        return
    width = c['width']
    target_int = c['target_int']
    if target_int is None:
        raw = c['target_raw']
        excess = len(raw) - width
        if c['target_real'] is None and excess > 0 and not raw[:excess].strip('0?'):
            c['target_raw'] = raw[excess:]
        return
    if target_int >= 0:
        return
    if target_int < -(1 << (width - 1)):
        raise _ConditionParseError(
            'condition {!r}: {} does not fit signal {} (width {}) as a two\'s-'
            'complement value; the signed range is {}..{}'.format(
                c['original'], c['value_text'], c['path'], width,
                -(1 << (width - 1)), (1 << (width - 1)) - 1))
    c['target_int'] = target_int + (1 << width)


def _resolve_conditions(vcd, text):
    """Parse and resolve one AND clause's signal patterns to signal ids."""
    resolved = []
    seen = set()
    for c in _parse_conditions(text):
        role = 'changed() signal' if c['kind'] == 'changed' else 'condition signal'
        sid = _resolve_one_signal(vcd, c['pattern'], role)
        c = dict(c)
        c['sid'] = sid
        c['path'] = vcd.signals[sid]['path']
        c['width'] = vcd.signals[sid]['width']
        # 1.4.0's precomputed kind table, which exists exactly so consumers
        # need not re-derive a signal's class from its declared type.
        c['kind_of_signal'] = vcd._sid_kind[sid]
        if c['kind'] == 'level':
            _check_term_kind(c)
            _fit_target_to_width(c)
        key = _term_key(c)
        if key in seen:
            continue
        seen.add(key)
        resolved.append(c)
    return resolved


def _resolve_clauses(vcd, texts):
    """Resolve every --condition into an OR clause list (OR-of-ANDs).

    Each --condition is one comma-separated AND clause; repeating the flag ORs
    the clauses. Duplicate clauses -- identical, term-order permuted, or
    alias-equivalent -- fold silently to the first occurrence, so a scripted
    caller that repeats a clause does not double the echoed condition. A single
    clause keeps exactly today's behavior, echo included.
    """
    if texts is None:
        raise _ConditionParseError('search requires --condition')
    if isinstance(texts, str):
        texts = [texts]
    clauses = []
    seen = set()
    for text in texts:
        clause = _resolve_conditions(vcd, text)
        key = tuple(sorted(_term_key(c) for c in clause))
        if key in seen:
            continue
        seen.add(key)
        clauses.append(clause)
    if not clauses:
        raise _ConditionParseError('search requires --condition')
    return clauses


def _resolve_show_sids(vcd, show_patterns):
    """Resolve --show patterns to one or more signal ids.

    Show positions are allowed to match multiple signals, but an exact full
    path still wins over substring matching for that specific pattern. This
    keeps `--show tb.data` from unexpectedly also selecting `tb.data_out`;
    users who want broad matching can still write `--show data` or use glob
    patterns such as `--show "*data*"`.
    """
    if not show_patterns:
        return []
    # Normalize even for list inputs.  argparse already does this for CLI
    # strings, but repeating the bounded, idempotent normalization keeps the
    # helper safe for programmatic callers as well.
    pats = _normalize_filter_patterns(show_patterns)
    if not pats:
        return []

    selected = set()
    missing = []
    for pat in pats:
        pat_text = str(pat).strip()
        exact = set()
        if '*' not in pat_text and '?' not in pat_text:
            pl = pat_text.lower()
            for sid, info in vcd.signals.items():
                for path in info['aliases']:
                    if path.lower() == pl:
                        exact.add(sid)
            if exact:
                selected.update(exact)
                continue

        matched = vcd.match([pat_text])
        if matched:
            selected.update(matched)
        else:
            missing.append(pat_text)

    if missing:
        raise _ConditionParseError(
            '--show matches no signals: {}'.format(', '.join(missing)))
    if not selected:
        raise _ConditionParseError('--show matches no signals')
    return sorted(selected, key=lambda sid: vcd.signals[sid]['path'])


def _conditions_hold(state, conditions, changed_sids=frozenset(),
                     ov_sid=None, ov_val=None):
    """Do all of one clause's AND terms hold?

    `state` maps sid to raw value; `changed_sids` is the set of signals that
    genuinely transitioned at the tick under evaluation (empty outside event
    mode, where no clause carries a changed() term).

    `ov_sid`/`ov_val` override one signal's value for this evaluation. Event
    mode uses it for the edge's own signal: everything else is read at the
    tick's settled state (so the answer does not depend on the order records
    happen to be written in), while the transitioning signal is read at the
    value it took AT that edge — which is what makes `changed(s),s=1` mean
    "rising edge of s" even when s toggles several times inside one tick.
    """
    for c in conditions:
        if c['kind'] == 'changed':
            if c['sid'] not in changed_sids:
                return False
            continue
        sid = c['sid']
        value = ov_val if sid == ov_sid else state.get(sid)
        if not _condition_match(
                value, c['op'], c['target_raw'],
                c['target_int'], c.get('width'), c.get('kind_of_signal'),
                c.get('target_real')):
            return False
    return True


def _any_clause_holds(state, clauses, changed_sids=frozenset()):
    """OR across clauses: the search holds when ANY clause's terms all hold.

    With a single clause this is exactly _conditions_hold, so single
    --condition behavior is unchanged.
    """
    for clause in clauses:
        if _conditions_hold(state, clause, changed_sids):
            return True
    return False


def _condition_label(conditions):
    return ','.join(c['original'] for c in conditions)


def _condition_result_text(conditions):
    return ','.join(
        'changed({})'.format(c['path']) if c['kind'] == 'changed'
        else '{}{}{}'.format(c['path'], c['op'], c['value_text'])
        for c in conditions)


def _join_clauses(clauses, render):
    """Echo the clause list: a lone clause as-is, several as `(..) OR (..)`.

    The single-clause form is deliberately unparenthesized so that every
    existing one-condition invocation echoes byte-for-byte as before.
    """
    if len(clauses) == 1:
        return render(clauses[0])
    return ' OR '.join('({})'.format(render(c)) for c in clauses)


def _show_values(vcd, state, show_sids, verbose=False, ov_sid=None, ov_val=None):
    """Return (values, meta) for show signals in current state.

    The return shape is intentionally stable regardless of verbose. meta is
    None unless verbose=True. This avoids type-dependent unpacking in search.

    `ov_sid`/`ov_val` override one signal, matching _conditions_hold: an event
    row shows the transitioning signal at the value it took at that edge, and
    every other shown signal at the tick's settled value.
    """
    values = {}
    meta = {} if verbose else None
    for sid in show_sids:
        info = vcd.signals[sid]
        path = info['path']
        raw = ov_val if sid == ov_sid else state.get(sid)
        values[path] = fmt_val(raw, info) if raw is not None else '(undef)'
        if verbose:
            meta[path] = {'raw': raw, 'width': info['width'], 'type': info.get('type', 'wire')}
    return values, meta


def _values_text(values):
    return ' '.join('{}={}'.format(k, v) for k, v in values.items())


def _search_end_time(vcd, t0, t1):
    tokens = vcd._data_token_lists(chunk_size=65536)
    try:
        _, saw_value, _ = vcd._scan_timestamps(tokens, stop_at_value=True)
    finally:
        tokens.close()
    if not saw_value:
        raise _ConditionParseError(
            'search cannot evaluate condition: VCD data section contains no value changes')
    if t1 is not None:
        return t1
    _mn, mx = vcd.scan_time_range()
    if mx is None:
        raise _ConditionParseError(
            'search cannot evaluate condition: VCD data section contains no value changes')
    return mx


def _event_groups(vcd, t0, t1, sids):
    """Yield (time, [(sid, val), ...]) groups in time order."""
    cur_t = None
    group = []
    for t, sid, val in vcd.iter_events(t0, t1, sids):
        if cur_t is None:
            cur_t = t
        if t != cur_t:
            yield cur_t, group
            cur_t, group = t, []
        group.append((sid, val))
    if cur_t is not None:
        yield cur_t, group


def _transition_groups(vcd, t0, t1, sids):
    """Yield (time, [(sid, prev, val, kind), ...]) groups in time order.

    _event_groups over the TRANSITIONS view: same per-timestamp grouping, but
    each record keeps the previously observed value and the signal kind, which
    is what lets event mode compute a tick's transition set (and so answer
    "did a and b change together?") without re-deriving either.
    """
    cur_t = None
    group = []
    for t, sid, prev, val, kind in vcd.iter_transitions(t0, t1, sids):
        if cur_t is None:
            cur_t = t
        if t != cur_t:
            yield cur_t, group
            cur_t, group = t, []
        group.append((sid, prev, val, kind))
    if cur_t is not None:
        yield cur_t, group


