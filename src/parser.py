# ================================================================
# Part 3: VCD parser
# ================================================================


# IEEE 1364-2005 declaration keywords that introduce a $<kw> ... $end section.
_DECL_KEYWORDS = {'$timescale', '$scope', '$upscope', '$var',
                  '$comment', '$date', '$version', '$enddefinitions'}

# Bracketed size/reference range, e.g. '[7:0]'. Tolerates a single-bit range
# written as a range (handled by the caller). Anchored so '[a:b]' rejects.
_HEADER_RANGE_RE = re.compile(r'\[(\d+):(\d+)\]$')


def _collect_bracket_tokens(tokens, i):
    """Join a bracketed reference that free-format VCD may split across tokens.

    Per IEEE 1364 free-format, a reference range can be split, e.g.
    'data [7 : 0]' -> ['data', '[7', ':', '0]']. Returns (joined, next_idx)
    when tokens[i] opens a '[', else (None, i). This is module-level (rather
    than nested in _parse_header) so the one-line fast path and the generic
    token parser share one definition and cannot drift apart.
    """
    if i >= len(tokens) or not tokens[i].startswith('['):
        return None, i
    parts = []
    while i < len(tokens):
        parts.append(tokens[i])
        if ']' in tokens[i]:
            return ''.join(parts), i + 1
        i += 1
    return None, i


def _parse_var_tokens(body, scope_path):
    """Parse the token body of a $var declaration (the tokens between '$var'
    and '$end').

    Returns (sym, name, width, bit_str, scope_path, vtype), or None for a
    malformed declaration that should be skipped. Raises _VCDResourceError for
    hostile widths. Shared by both the one-line header fast path and the
    generic multi-line token parser so var interpretation is defined once.
    """
    if len(body) < 4:
        return None
    nbody = len(body)

    # Fast path for the two overwhelmingly common shapes emitted by VCS,
    # Verilator, Icarus, etc., where the size is a plain integer (not a split
    # '[ msb : lsb ]') and the reference is at most one trailing '[..]' token:
    #   4 tokens: vtype width sym name                  (scalar / packed bus)
    #   5 tokens: vtype width sym name [range-or-bit]   (bus or bit-select)
    # This avoids the two _collect_bracket_tokens scans per variable on files
    # that declare hundreds of thousands of them. Any shape that does not match
    # (bracketed size, split range, extra tokens) falls through to the general
    # parser below, so behaviour is unchanged for those.
    if nbody <= 5:
        b1 = body[1]
        if not b1.startswith('['):
            w = _safe_int_digits(b1)
            if w is not None:
                if w <= 0 or w > MAX_SIGNAL_WIDTH:
                    raise _VCDResourceError(
                        '$var width {} exceeds max {}; '
                        'file may be corrupt or malicious'.format(w, MAX_SIGNAL_WIDTH))
                vtype = body[0]
                sym = body[2]
                name = body[3]
                if nbody == 4:
                    return sym, name, w, None, scope_path, vtype
                # nbody == 5: trailing reference token body[4].
                ref = body[4]
                if ref.startswith('[') and ref.endswith(']'):
                    if w > 1:
                        # Range folded into displayed name ('data[7:0]').
                        return sym, name + ref, w, None, scope_path, vtype
                    # 1-bit [N]: keep as bit_str for the bit-explosion heuristic.
                    return sym, name, w, ref, scope_path, vtype
                # Unexpected 5th token (e.g. split '[7 :'); fall through.

    vtype = body[0]
    size_expr, idx_after_size = _collect_bracket_tokens(body, 1)
    if size_expr is not None:
        m = _HEADER_RANGE_RE.match(size_expr)
        if not m:
            return None
        msb = _safe_int_digits(m.group(1))
        lsb = _safe_int_digits(m.group(2))
        if msb is None or lsb is None:
            return None
        w = abs(msb - lsb) + 1
        idx = idx_after_size
    else:
        w = _safe_int_digits(body[1])
        if w is None:
            return None
        idx = 2
    # Refuse pathological widths before they reach fmt_val (which would try to
    # allocate pad bytes proportional to width). Real signals never approach
    # MAX_SIGNAL_WIDTH.
    if w <= 0 or w > MAX_SIGNAL_WIDTH:
        raise _VCDResourceError(
            '$var width {} exceeds max {}; '
            'file may be corrupt or malicious'.format(w, MAX_SIGNAL_WIDTH))
    if len(body) <= idx + 1:
        return None
    sym, name = body[idx], body[idx + 1]
    # A bracket after the name is a bit/range reference, possibly split across
    # tokens. For multi-bit refs with a range, fold it into the displayed name
    # ('data[7:0]'); for a 1-bit ref with [N], keep bit_str for the
    # bit-explosion heuristic.
    bit_str, _idx_after_ref = _collect_bracket_tokens(body, idx + 2)
    if bit_str is not None and w > 1:
        name = name + bit_str
        bit_str = None
    return sym, name, w, bit_str, scope_path, vtype


# Simulation keywords that wrap value_changes until $end. The keyword and $end
# are pure markers — the wrapped value_changes are parsed normally.
# Four-state VCD (18.2.3.9-12) + extended VCD (18.4.1 BNF).
_SIM_KEYWORDS = {'$dumpall', '$dumpoff', '$dumpon', '$dumpvars',
                 '$dumpports', '$dumpportsoff', '$dumpportson', '$dumpportsall'}

# ASCII whitespace byte values — the exact set bytes.split() (no separator)
# breaks on. Used by the t_max tail scan to find token boundaries when
# stitching a token split across a fixed-size read.
_ASCII_WS_BYTES = frozenset(b' \t\n\r\f\v')


class VCDParser:
    """Streaming VCD parser. Token-based: handles single-line and multi-line
    sections, inline simulation keyword blocks, and multi-line port values
    per IEEE 1364-2005 Section 18.

    Auto-reassembles bit-exploded signals (QuestaSim writes 512-bit signals
    as 512 individual 1-bit $var entries with [N] suffix).

    Extended VCD ($dumpports) support level: port_state characters are
    lowered to 4-state values (0/1/x/z) for RTL debug. The strength0 and
    strength1 components are parsed but discarded — preserving them would
    rarely benefit RTL-level analysis and clutters the value display.
    """

    def __init__(self, path):
        self.path = path
        self.ts_str = ''
        self.ts_sec = 1e-12        # timescale in seconds
        self.signals = {}           # sig_id -> {path, width, type, aliases}
        self._data_offset = 0
        # Header metadata per IEEE 1364-2005 18.2.3:
        #   $date    - simulation date string (18.2.3.2)
        #   $version - simulator vendor/version (18.2.3.3)
        #   $comment - free-form, may appear multiple times (18.2.3.1)
        # Captured verbatim for provenance display; an agent inspecting an
        # unknown VCD benefits from knowing which simulator produced it
        # (QuestaSim 2023.1 vs Icarus Verilog vs VCS) and when, since
        # downstream debug heuristics may depend on simulator quirks.
        self.date = ''
        self.version = ''
        self.comments = []
        # If $enddefinitions $end is followed by data tokens on the same
        # line(s) buffered by readline, those tokens replay first in data.
        self._initial_tokens = []
        self._bit_map = {}          # sym -> list of (sig_id, bit_index)
        self._bit_state_template = {}  # sig_id -> initial bit list for replay-local reassembly
        self._parse_header()

    def _parse_header(self):
        """Parse VCD declarations and record where value changes begin.

        Common generated VCDs put one complete declaration per physical line
        ('$var wire 1 ! clk $end'). Those lines are handled by a direct fast
        path that avoids the per-token state machine; VCS/Verdi/GTKWave files
        can carry hundreds of thousands of $var records, so this materially
        cuts startup time for every command. Free-format lines fall through to
        the tolerant token parser: multi-line declarations, and — because VCD is
        free-format — several declarations packed onto one physical line
        ('$var .. $end $var .. $end', or two $scope). The fast path is taken only
        when the line holds exactly one self-contained declaration (a single
        trailing $end); both paths feed the same _parse_var_tokens helper, so the
        parsed signal table is identical regardless of which path a line takes
        (asserted by the header-equivalence tests, including multi-declaration
        and indented lines)."""
        scope = []
        scope_path = ''
        raw_vars = []  # (sym, name, width, bit_idx_str, scope_path, vtype)
        current_kw = None
        body = []
        done = False
        append_raw = raw_vars.append

        def _append_var(body_tokens):
            if len(raw_vars) >= MAX_VARS:
                raise _VCDResourceError(
                    'too many $var declarations: more than {}. '
                    'Set VCD_ANALYZER_MAX_VARS to raise the limit.'.format(MAX_VARS))
            rec = _parse_var_tokens(body_tokens, scope_path)
            if rec is not None:
                append_raw(rec)

        ts_valid = None   # None: no $timescale seen; False: unparseable body
        first_line = True
        with open(self.path, 'r', encoding='utf-8', errors='replace') as f:
            while not done:
                line = f.readline(MAX_DATA_TOKEN_LEN + 1)
                if not line:
                    break
                if first_line:
                    # A UTF-8 byte-order mark glued to the first keyword hid
                    # it ('\ufeff$timescale'), silently falling back to 1 ps.
                    first_line = False
                    if line.startswith('\ufeff'):
                        line = line[1:]
                if len(line) == MAX_DATA_TOKEN_LEN + 1 and not line[-1].isspace():
                    tail_len = len(line.rsplit(None, 1)[-1])
                    suffix = []
                    while True:
                        if tail_len > MAX_DATA_TOKEN_LEN:
                            raise _VCDResourceError('VCD token exceeds {} characters'.format(MAX_DATA_TOKEN_LEN))
                        ch = f.read(1)
                        if not ch:
                            break
                        suffix.append(ch)
                        if ch.isspace():
                            break
                        tail_len += 1
                    line += ''.join(suffix)
                toks = line.split()
                _check_token_lengths(toks)

                # Fast path: one complete declaration on this line, with $end
                # on the same line, and we are not mid-section. Anything that
                # does not fit falls through to the generic token parser, so
                # correctness never depends on the fast path matching.
                if current_kw is None:
                    stripped = line.strip()
                    if stripped:
                        # Valid ONLY for a single self-contained declaration:
                        # exactly one $end, as the final token. A free-format
                        # line may legally pack several declarations
                        # ('$var .. $end $var .. $end', two $scope); those carry
                        # an interior $end and MUST fall through to the token
                        # parser below, which handles repeated keyword..$end
                        # groups. Gating on a single trailing $end is what keeps
                        # the fast and generic paths' signal tables identical.
                        single = toks[-1] == '$end' and toks.count('$end') == 1
                        if single and stripped.startswith('$var '):
                            if len(toks) >= 6:
                                _append_var(toks[1:-1])
                                continue
                        elif single and stripped.startswith('$scope '):
                            if len(toks) >= 4:
                                if len(scope) >= MAX_SCOPE_DEPTH:
                                    raise _VCDResourceError(
                                        '$scope nesting depth exceeds {}; '
                                        'file may be corrupt or malicious'.format(MAX_SCOPE_DEPTH))
                                scope.append(toks[2])
                                scope_path = '.'.join(scope)
                                continue
                        elif single and stripped == '$upscope $end':
                            if scope:
                                scope.pop()
                                scope_path = '.'.join(scope)
                            continue
                        elif single and stripped.startswith('$timescale '):
                            ts_body = ' '.join(toks[1:-1])
                            self.ts_str = '$timescale ' + ts_body + ' $end'
                            ts_parsed = _parse_timescale_strict(ts_body)
                            ts_valid = ts_parsed is not None
                            self.ts_sec = ts_parsed if ts_valid else 1e-12
                            continue
                        elif single and (stripped.startswith('$date ') or
                                         stripped.startswith('$version ') or
                                         stripped.startswith('$comment ')):
                            kw = toks[0]
                            text = ' '.join(toks[1:-1])
                            if kw == '$date':
                                self.date = text
                            elif kw == '$version':
                                self.version = text
                            elif len(self.comments) < MAX_COMMENTS:
                                self.comments.append(text)
                            continue
                        # $enddefinitions is intentionally NOT fast-pathed:
                        # data tokens may share its line and the generic loop
                        # below already buffers them into _initial_tokens with
                        # the correct fail-fast cap.

                for tok in toks:
                    if done:
                        # Buffer tokens that share the same line as
                        # `$enddefinitions $end`. These are data tokens
                        # (value_changes, timestamps), so they MUST NOT
                        # be silently dropped — that would corrupt the
                        # waveform without the user noticing. Fail-fast.
                        if len(self._initial_tokens) >= MAX_INITIAL_TOKENS:
                            raise _VCDResourceError(
                                'too many data tokens on the same line as '
                                '$enddefinitions $end (>{}); file may be '
                                'corrupt or malicious'.format(MAX_INITIAL_TOKENS))
                        self._initial_tokens.append(tok)
                        continue
                    if current_kw is None:
                        if tok in _DECL_KEYWORDS:
                            current_kw = tok
                            body = []
                        # else: stray token, ignore
                    elif tok == '$end':
                        # Section complete
                        if current_kw == '$timescale':
                            ts_body = ' '.join(body)
                            self.ts_str = '$timescale ' + ts_body + ' $end'
                            ts_parsed = _parse_timescale_strict(ts_body)
                            ts_valid = ts_parsed is not None
                            self.ts_sec = ts_parsed if ts_valid else 1e-12
                        elif current_kw == '$scope' and len(body) >= 2:
                            # Cap nesting depth to defend against
                            # 1M-level $scope-without-$upscope construction.
                            if len(scope) >= MAX_SCOPE_DEPTH:
                                raise _VCDResourceError(
                                    '$scope nesting depth exceeds {}; '
                                    'file may be corrupt or malicious'.format(MAX_SCOPE_DEPTH))
                            scope.append(body[1])
                            scope_path = '.'.join(scope)
                        elif current_kw == '$upscope':
                            if scope:
                                scope.pop()
                                scope_path = '.'.join(scope)
                        elif current_kw == '$var':
                            _append_var(body)
                        elif current_kw == '$enddefinitions':
                            done = True
                        elif current_kw == '$date':
                            # Tokens collapsed to single-spaced string;
                            # original used \t / multi-line for readability.
                            self.date = ' '.join(body)
                        elif current_kw == '$version':
                            self.version = ' '.join(body)
                        elif current_kw == '$comment':
                            # Per 18.2.3.1, $comment may appear multiple
                            # times. Silent drop after the cap is safe:
                            # comments are metadata, not data.
                            if len(self.comments) < MAX_COMMENTS:
                                self.comments.append(' '.join(body))
                        current_kw = None
                    else:
                        # Bound section body. In practice this only
                        # truncates oversized $comment / $date / $version
                        # bodies — metadata. $var bodies are 4-8 tokens,
                        # $scope is 2, $timescale is 2; none come close
                        # to the cap.
                        if len(body) < MAX_HEADER_BODY_TOKENS:
                            body.append(tok)
            self._data_offset = f.tell()

        # Resolved here, surfaced by main() on stderr: a missing or unreadable
        # $timescale silently scaled every reported time by the 1 ps default.
        if ts_valid is None:
            self.timescale_warning = 'no $timescale declaration; assuming 1ps'
        elif not ts_valid:
            self.timescale_warning = 'cannot parse {}; assuming 1ps'.format(self.ts_str)
        else:
            self.timescale_warning = None

        # Phase 2: detect and reassemble bit-exploded signals.
        # Bit-exploded heuristic per QuestaSim convention: each bit is a
        # 1-bit $var with [N] suffix. We auto-reassemble ONLY when the bit
        # indices form a complete 0..max_bit contiguous set. Standard-legal
        # partial dumps (e.g. only $var ... bus[4] ... emitted) must NOT be
        # synthesized as a bus[4:0] with phantom lower bits — they are kept
        # as individual bit-select references.
        bit_groups = defaultdict(dict)  # (scope, base_name) -> {bit_idx: sym}
        bit_types = {}                   # (scope, base_name) -> vtype
        duplicate_bit_groups = set()      # groups with duplicate bit indices; never reassemble
        standalone = []
        bit_select_singletons = []       # (sym, name, idx, sc, vtype)

        for sym, name, w, bit_str, sc, vtype in raw_vars:
            if w == 1 and bit_str is not None:
                m = re.match(r'\[(\d+)\]', bit_str)
                if m:
                    idx = _safe_int_digits(m.group(1))
                    if idx is None:
                        # Overlong/malformed bit index — treat the $var as
                        # a standalone signal (its bit_str folded back).
                        standalone.append((sym, name + bit_str, 1, sc, vtype))
                        continue
                    group_key = (sc, name)
                    group = bit_groups[group_key]
                    if idx in group:
                        # Illegal VCD: duplicate bit-select declaration for the
                        # same reconstructed bus bit.  Do not silently let the
                        # later symbol overwrite the earlier one; mark the group
                        # non-reassemblable so all raw bit-select declarations
                        # remain visible as standalone signals.
                        duplicate_bit_groups.add(group_key)
                    else:
                        group[idx] = sym
                    # Resource cap: refuse to allocate gigantic synthesized
                    # buses (per-call template copy cost scales linearly).
                    # Default 65536 is 128× typical QuestaSim bit-bus size;
                    # tune via VCD_ANALYZER_MAX_REASSEMBLE_BITS env var.
                    if len(group) > MAX_REASSEMBLE_BITS:
                        raise _VCDResourceError(
                            'bit-exploded group {}.{} has more than {} bits. '
                            'Set VCD_ANALYZER_MAX_REASSEMBLE_BITS to raise the limit.'.format(
                                sc or '<root>', name, MAX_REASSEMBLE_BITS))
                    bit_types[(sc, name)] = vtype
                    bit_select_singletons.append((sym, name, idx, sc, vtype))
                    continue
                # A 1-bit reference written as a range (for example
                # data[0:0]) is not a bit-exploded bus bit. Preserve the
                # reference suffix in the displayed path instead of silently
                # dropping it. Some simulators emit this non-canonical form.
                standalone.append((sym, name + bit_str, 1, sc, vtype))
                continue
            standalone.append((sym, name, w, sc, vtype))

        # Partition bit_groups: a contiguous run lo..hi with ≥2 bits →
        # reassemble as name[hi:lo] (a field such as bus[15:8] is a legal
        # part-select dump; no phantom bits outside the declared run are
        # synthesized); everything else → individual bit-select references.
        # A single '[N]' declaration alone is NOT a bus.
        #
        # DoS guard: do NOT compute set(range(lo, hi+1)) — a malicious VCD with
        # 'bus[0]' + 'bus[1000000000]' would force materialization of a
        # billion-element set (gigabytes of RAM). Distinct indices form a
        # contiguous run iff count == hi - lo + 1, an O(n) min/max check.
        non_contiguous = set(duplicate_bit_groups)
        for key, bits in bit_groups.items():
            if key in non_contiguous:
                continue
            indices = bits.keys()
            n = len(indices)
            if n < 2:
                non_contiguous.add(key)
                continue
            if max(indices) - min(indices) + 1 != n:
                non_contiguous.add(key)

        # Each non-contiguous bit-select becomes a standalone 'name[idx]' signal
        for sym, name, idx, sc, vtype in bit_select_singletons:
            if (sc, name) in non_contiguous:
                standalone.append((sym, '{}[{}]'.format(name, idx), 1, sc, vtype))

        # Register standalone signals. Per IEEE 1364-2005 18.2.3.7, the same
        # identifier_code can be referenced under multiple paths. First seen
        # type wins when aliases have different var_types.
        for sym, name, w, sc, vtype in standalone:
            path = '{}.{}'.format(sc, name) if sc else name
            if sym in self.signals:
                self.signals[sym]['aliases'].append(path)
                if sc and sc not in self.signals[sym].setdefault('scopes', []):
                    self.signals[sym]['scopes'].append(sc)
            else:
                self.signals[sym] = {
                    'path': path, 'width': w, 'type': vtype,
                    'aliases': [path], 'scope': sc, 'scopes': [sc] if sc else []
                }

        for (sc, name), bits in bit_groups.items():
            if not bits or (sc, name) in non_contiguous:
                continue
            max_bit = max(bits.keys())
            min_bit = min(bits.keys())
            width = max_bit - min_bit + 1
            ref = '{}[{}:{}]'.format(name, max_bit, min_bit)
            path = '{}.{}'.format(sc, ref) if sc else ref
            sig_id = '__grp__{}__{}'.format(sc, name)
            self.signals[sig_id] = {
                'path': path, 'width': width,
                'type': bit_types.get((sc, name), 'wire'),
                'aliases': [path], 'scope': sc, 'scopes': [sc] if sc else [],
                'synthesized': True,    # bit-exploded reassembled bus
                'raw_bits': len(bits),  # number of $var declarations consumed
            }
            self._bit_state_template[sig_id] = ['x'] * width
            # Per IEEE 1364-2005 18.2.3.7, the same identifier_code can be
            # referenced under multiple paths. When two bit-exploded buses
            # share per-bit identifier codes (e.g. bus[0]/aliasbus[0] both
            # use '!'), each is a separate synthesized signal that must
            # update independently. _bit_map is therefore 1-to-many.
            for idx, sym in bits.items():
                self._bit_map.setdefault(sym, []).append((sig_id, idx - min_bit))

        # Raw $var counts (transparent to IEEE 1364 spec) so 'info' can
        # report accurate metadata even when reassembly collapses many
        # declarations into a single synthesized bus. Distinct from
        # `signal_count` (post-reassembly view used by agent commands).
        self.raw_var_count = len(raw_vars)
        self.raw_type_counts = defaultdict(int)
        for _sym, _name, _w, _bit_str, _sc, vtype in raw_vars:
            self.raw_type_counts[vtype] += 1

        # Precomputed signal "kind" — the single source of truth for the
        # event/state layering. Building these once here removes the per-event
        # signals.get(sid)['type'] lookup that _iter_changes' no-op bypass used
        # to pay on the value-change hot path, and lets the transition stream
        # carry a first-class kind so consumers (summary/search) no longer
        # re-derive type == 'event' themselves.
        #   _event_sids: sids whose declared var_type is 'event' (markers, not
        #     levels) — event triggers bypass no-op coalescing; each one counts.
        #   _sid_kind:   sid -> {'event','real','vector','scalar'}, from declared
        #     type + width (synthesized bit-buses are vectors).
        self._event_sids = frozenset(
            sid for sid, _info in self.signals.items()
            if _info.get('type') == 'event')
        self._sid_kind = {}
        for _sid, _info in self.signals.items():
            _vt = _info.get('type')
            if _vt == 'event':
                self._sid_kind[_sid] = 'event'
            elif _vt in ('real', 'realtime'):
                self._sid_kind[_sid] = 'real'
            elif _info.get('width', 1) > 1 or _info.get('synthesized'):
                self._sid_kind[_sid] = 'vector'
            else:
                self._sid_kind[_sid] = 'scalar'
        # Declared width of every multi-bit logic signal. Writers drop redundant
        # MSBs (IEEE 1364 Table 18-1), so 'b11' and 'b0011' are the same 4-bit
        # value; the change stream left-extends short vector values to this
        # width so no-op suppression, summary counts and compare see one
        # canonical spelling instead of reporting '3 -> 3' as a change.
        self._vec_width = {
            _sid: _info['width'] for _sid, _info in self.signals.items()
            if self._sid_kind[_sid] == 'vector' and _info['width'] > 1}

    def match(self, keywords):
        """Return set of sig_ids matching any pattern, or None for all.

        Plain patterns use case-insensitive substring matching. Patterns
        containing '*' or '?' use the tool's minimal glob-lite matching:
        '*' matches any span, '?' matches one character, and all other
        characters are literal. This intentionally differs from fnmatch:
        '[' and ']' are NOT character-class delimiters because VCD bus ranges
        like data[7:0] are common signal names.

        Input is normalized through _normalize_filter_patterns to bound
        pattern length and wildcard count.
        """
        if not keywords:
            return None
        raw_pats = [k.lower() for k in _normalize_filter_patterns(keywords) or []]
        if not raw_pats:
            return None
        pats = []
        for pat in raw_pats:
            if any(ch in pat for ch in '*?'):
                pats.append(('glob', _glob_lite_regex(pat)))
            else:
                pats.append(('substr', pat))
        out = set()
        for sid, info in self.signals.items():
            for path in info['aliases']:
                pl = path.lower()
                hit = False
                for kind, pat in pats:
                    hit = pat.match(pl) is not None if kind == 'glob' else pat in pl
                    if hit:
                        out.add(sid)
                        break
                if hit:
                    break
        return out

    def _data_token_lists(self, chunk_size=None):
        """Yield successive non-empty token batches from the data section.

        The buffered initial tokens (those that trailed ``$enddefinitions`` on
        the same read) are yielded first. The data section is then read in
        large chunks and split in C, rather than iterated line by line: an
        FST-to-VCD converter can emit tens of millions of one-token lines, and
        per-line Python iteration dominates tokenizer time on those. A carry
        buffer holds any partial token spanning a chunk boundary, so the flat
        token stream is byte-for-byte identical to line-based ``.split()`` —
        verified exhaustively against the line-based reference across chunk
        sizes and adversarial whitespace.

        ``chunk_size`` overrides the read size. iter_events() uses the default
        (large, env-tunable) chunk; scan_time_range()'s t_min passes a small
        chunk and consumes lazily (it stops at the first ``#T``), so it never
        reads more than the head it needs.
        """
        if self._initial_tokens:
            yield list(self._initial_tokens)

        if chunk_size is None:
            chunk_size = _env_int('VCD_ANALYZER_TOKEN_CHUNK_SIZE', 4 * 1024 * 1024)
        if chunk_size < 65536:
            chunk_size = 65536
        carry = ''
        with open(self.path, 'r', encoding='utf-8', errors='replace') as f:
            f.seek(self._data_offset)
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                if carry:
                    chunk = carry + chunk
                    carry = ''
                # If the chunk does not end on whitespace its final token may be
                # truncated. Cut at the last whitespace, tokenize the complete
                # prefix, and carry the remainder. rfind over the six VCD
                # whitespace chars stays in C (no per-character Python scan).
                if not chunk[-1].isspace():
                    cut = max(chunk.rfind(' '), chunk.rfind('\n'), chunk.rfind('\t'),
                              chunk.rfind('\r'), chunk.rfind('\v'), chunk.rfind('\f'))
                    if cut < 0:
                        carry = chunk
                        _check_token_lengths((carry,))
                        continue
                    carry = chunk[cut + 1:]
                    _check_token_lengths((carry,))
                    chunk = chunk[:cut]
                toks = chunk.split()
                _check_token_lengths(toks)
                if toks:
                    yield toks
        if carry:
            tail = carry.split()
            _check_token_lengths(tail)
            if tail:
                yield tail

    def _is_structural_token(self, tok):
        """Return True when tok is structural rather than an identifier_code.

        Only #<digits> has positional ambiguity: it can be a timestamp at
        top level, or a legal identifier_code after b/r/p. If such a token is
        declared as a normal signal or bit-exploded bit, it is the symbol;
        otherwise it is structural and must be pushed back so the outer loop
        can process it as a timestamp.
        """
        if tok is None:
            return True
        if tok.startswith('#') and len(tok) > 1 and tok[1].isdigit():
            return tok not in self.signals and tok not in self._bit_map
        return False

    def _consume_value_change(self, tok, next_token, pushback):
        """Parse one VCD value_change token sequence.

        Returns (identifier_code, value_str) on a valid value_change, or None
        when tok is malformed / not a value_change. This is the single shared
        validation path used by iter_events() and scan_time_range(), so info's
        reported time range stays aligned with dump/search parsing behavior.

        next_token is a zero-arg function over the same pushback-capable token
        stream as the caller. If a token consumed while validating b/r/p turns
        out to be structural, it is pushed back in the same order used by the
        old local parsers.
        """
        if not tok:
            return None
        first = tok[0]

        if first in '01xXzZ':
            sym = tok[1:]
            if not sym:
                return None
            return sym, first.lower()

        if first in 'bB':
            bits = tok[1:]
            # Consume the identifier_code BEFORE validating the value. A b-token
            # opener always owns the next token as its identifier (unless that
            # token is structural — a timestamp — which is pushed back).
            # Validating first and returning without consuming would leak a
            # malformed value's identifier back to the top level, where e.g.
            # 'b1012 1&' re-parses '1&' as a scalar change on signal '&' — a
            # phantom event. See test_freeformat.py (B4).
            sym = next_token()
            if self._is_structural_token(sym):
                if sym is not None:
                    pushback.append(sym)
                return None
            if not bits or bits.translate(_DEL_4STATE_CI):
                return None
            return sym, bits.lower()

        if first in 'rR':
            body = tok[1:]
            # Consume the identifier_code before validating (see the b-token
            # note above): 'rnan x!' must not leak 'x!' back to be mis-read as a
            # scalar change. Non-finite %g output (inf/nan, including nan
            # payloads like 'nan(ind)') is a legal real_number and is kept;
            # see _REAL_NONFINITE_RE.
            sym = next_token()
            if self._is_structural_token(sym):
                if sym is not None:
                    pushback.append(sym)
                return None
            if len(body) > _REAL_MAX_LEN or not (
                    _REAL_RE.match(body) or _REAL_NONFINITE_RE.match(body)):
                return None
            return sym, body

        if first == 'p':
            # Extended VCD (18.4.3.1): p<state> <s0> <s1> <id>.
            # Keep this validation in one place so malformed port events are
            # treated identically by iter_events() and scan_time_range().
            state = tok[1:] if len(tok) > 1 else ''
            if not state or any(c not in _PORT_STATE for c in state):
                return None

            s0 = next_token()
            if s0 is None or len(s0) != 1 or s0 not in '01234567':
                if s0 is not None:
                    pushback.append(s0)
                return None

            s1 = next_token()
            if s1 is None or len(s1) != 1 or s1 not in '01234567':
                if s1 is not None:
                    pushback.append(s1)
                pushback.append(s0)
                return None

            sym = next_token()
            if self._is_structural_token(sym):
                if sym is not None:
                    pushback.append(sym)
                pushback.append(s1)
                pushback.append(s0)
                return None
            return sym, ''.join(_PORT_STATE[c] for c in state)

        return None

    def _scan_timestamps(self, token_lists, stop_at_first=False, resync=False,
                         stop_at_value=False):
        """Replay iter_events()'s top-level grammar over token_lists, ignoring
        the values themselves, to extract timestamps for scan_time_range().

        Returns ``(first_ts, saw_value_before_first_ts, last_ts)`` with each
        ``#T`` parsed by the hardened ``_parse_vcd_timestamp_token``. This is
        the single forward scanner shared by both ends of scan_time_range(),
        finally making _consume_value_change()'s "shared with scan_time_range()"
        contract true: info's time range is derived by exactly the rules
        iter_events() parses with —

          * ``$end`` and ``_SIM_KEYWORDS`` ($dumpvars/$dumpall/...) are
            top-level markers; any other ``$section`` ($comment/$vcdclose/
            unknown) has its body drained to the matching ``$end``;
          * a top-level ``#<digits>`` is ALWAYS a timestamp (no
            ``_is_structural_token`` gate at top level — matching iter_events);
          * ``b``/``r``/``p`` value changes go through _consume_value_change(),
            so a ``#<digits>`` that is a *declared identifier_code operand* is
            consumed rather than miscounted, and a pushed-back structural
            operand is re-read at top level exactly as the parser does.

        ``stop_at_first`` returns at the first top-level ``#T`` (t_min, which
        feeds tokens from ``_data_offset`` — a real top-level sync point).

        ``resync`` (t_max tail windows only): the window may begin inside a
        section body. Assume top level, but if a bare ``$end`` is met before any
        ``$X`` opener has confirmed the sync, the window began inside a drained
        section ($comment/$vcdclose) — discard the timestamps mis-read so far
        and resume at top level after that ``$end``. Since t_max scans the whole
        window and a trailing section's own ``$end`` is always inside an
        EOF-anchored window, a section-body ``#<digits>`` can never survive as
        the reported t_max.
        """
        pushback = []
        it = iter(token_lists)
        toks = ()
        ntoks = 0
        ti = 0

        def _next():
            nonlocal toks, ntoks, ti
            if pushback:
                return pushback.pop()
            while ti >= ntoks:
                nl = next(it, None)
                if nl is None:
                    return None
                toks = nl
                ntoks = len(nl)
                ti = 0
            tok = toks[ti]
            ti += 1
            return tok

        first_ts = None
        last_ts = None
        saw_value = False
        skipping = False        # inside a drained $comment/$vcdclose/unknown body
        synced = not resync     # top-level sync confirmed (no pending resync)

        while True:
            tok = _next()
            if tok is None:
                break
            if skipping:
                if tok == '$end':
                    skipping = False
                continue
            c0 = tok[0]
            if c0 == '$':
                if tok == '$end':
                    if not synced:
                        # Stray $end before any opener: the window began inside a
                        # section body — drop what we mis-read and resync.
                        first_ts = last_ts = None
                        saw_value = False
                        synced = True
                    continue
                # Any other '$X' is a real top-level structural marker.
                synced = True
                if tok in _SIM_KEYWORDS:
                    continue
                skipping = True     # $comment/$vcdclose/unknown -> drain to $end
                continue
            if c0 == '#' and len(tok) > 1 and tok[1].isdigit():
                v = _parse_vcd_timestamp_token(tok)
                if v is None:
                    continue        # malformed (e.g. '#1.5'); tolerate
                if first_ts is None:
                    first_ts = v
                last_ts = v
                if stop_at_first:
                    return first_ts, saw_value, last_ts
                continue
            # ---- value change (the value itself is irrelevant here) ----
            parsed = None
            if c0 in '01xXzZ' and len(tok) > 1:
                parsed = tok[1:], tok[0]
            elif c0 in 'bBrRp':
                parsed = self._consume_value_change(tok, _next, pushback)
            if parsed is not None:
                if stop_at_value:
                    if parsed[0] in self.signals or parsed[0] in self._bit_map:
                        return first_ts, True, last_ts
                else:
                    saw_value = True
            # else: stray token (bare '#', 'b', ...) — ignore
        return first_ts, saw_value, last_ts

    def iter_events(self, t0=0, t1=None, sids=None):
        """Yield (time, sig_id, value_str) with bit reassembly.

        Token-based, context-sensitive. Section keywords ($comment/$vcdclose/
        $dumpvars/$dumpoff/$dumpon/$dumpall/$dumpports*) are only recognized
        when the parser is at a top-level position (expecting either a
        timestamp or a value_change opener). After 'b<bits>', 'r<num>', or
        'p<state> <s0> <s1>' the NEXT token is consumed as identifier_code
        even if it happens to be the string '$comment' (legal per
        IEEE 1364-2005 18.2.1: identifier_code is any printable ASCII).

        Initial value changes appearing before any '#T' timestamp are
        emitted at logical t=0 (typical case: $dumpvars block directly
        after $enddefinitions without a leading #0).

        Multiple value_changes per timestamp are emitted: the IEEE 1364
        grammar allows any number of value_changes per simulation_time, and a
        writer may legally emit several for the same identifier within one
        timestamp (delta-cycle style dumps). A record that merely re-asserts a
        signal's current value is a no-op and adds no event: consecutive
        identical records for a signal coalesce (a '1a 1a' pair is one event),
        and the previously observed value is tracked across timestamp
        boundaries so a $dumpall/$dumpon checkpoint re-emitting the current
        value stays a no-op (the 1.3.19 static/active accounting is preserved). Event variables are
        markers, not levels: every record counts ('VCD event variables count
        each trigger'). Snapshot/compare last-write-wins semantics are
        unchanged.
        """
        for time, sid, _prev, val in self._iter_changes(t0, t1, sids):
            yield time, sid, val

    def iter_transitions(self, t0=0, t1=None, sids=None):
        """Per-signal transition stream: yield (time, sid, prev, value, kind).

        Same ordering and no-op/event semantics as iter_events, but each event
        also carries the previously observed value (prev; None on first
        observation) and the precomputed signal kind ('event'/'real'/'vector'/
        'scalar'), so consumers (summary, search) need not track prior state or
        re-derive type themselves. This is the TRANSITIONS view of the change
        stream.
        """
        sid_kind = self._sid_kind
        for time, sid, prev, val in self._iter_changes(t0, t1, sids):
            yield time, sid, prev, val, sid_kind[sid]

    def _iter_changes(self, t0=0, t1=None, sids=None):
        """Core change stream: yield (time, sid, prev, value) per value_change.

        Single semantic core behind iter_events (drops prev),
        iter_transitions (adds kind) and the state_* folds. Owns no-op
        coalescing, cross-timestamp last_val persistence, event-variable
        trigger counting, bit-exploded bus assembly, the t0 catch-up and
        the sids laziness. See iter_events for the value-change fidelity
        contract; prev is the value seen before this change (None on first
        observation).
        """
        cur_t = 0
        pending = []       # ordered [(sid, val), ...] — preserves intra-timestamp order
        last_val = {}      # sid -> previously observed value (no-op suppression)

        def _record(sid, val):
            # Append unless this is a no-op re-assertion of the previously
            # observed value. Event variables skip the check: their records
            # are trigger markers and each one counts. prev (the value seen
            # before this change, or None on first observation) rides along
            # so the transition view need not recompute it.
            prev = last_val.get(sid)
            if sid not in self._event_sids and prev == val:
                return
            pending.append((sid, prev, val))
            last_val[sid] = val

        # Synthesized bit-exploded buses are written one bit per record, so the
        # per-record view would expose cross-bit intermediates ('xx0','x00',
        # '000') that never existed in the design. Buffer each bus's bit writes
        # per tick and record the assembled value once at the tick boundary; a
        # second write to the SAME bit inside one tick is a genuine delta-cycle
        # step, so the bus value is recorded before that bit is overwritten.
        bus_dirty = {}     # gid -> set of bit indices written in the current tick

        def _commit_buses():
            for gid in bus_dirty:
                _record(gid, ''.join(reversed(bit_state[gid])))
            bus_dirty.clear()

        def _flush():
            if bus_dirty:
                _commit_buses()
            if not pending:
                return []
            items = list(pending)
            pending.clear()
            # last_val is deliberately NOT cleared: it is the running
            # "previously observed value" used to suppress no-op re-emissions
            # across timestamp boundaries (e.g. $dumpall checkpoints).
            return items

        # Flattened tokenizer. The data section is consumed as a sequence of
        # per-line token *lists* (self._data_token_lists); the main loop reads
        # the current list by index, so only line boundaries pay a next() call
        # — the per-token generator resume that dominated tokenizer time on
        # large files is gone. Pushback is honored on every read, so the b/r/p
        # look-ahead and $-section skipping keep their exact prior semantics.
        list_iter = self._data_token_lists()
        pushback = []
        signals = self.signals
        vec_width = self._vec_width
        toks = ()
        ntoks = 0
        ti = 0
        # Replay-local bit state. iter_events() must be pure with respect
        # to parser metadata: compare/search/summary/snapshot may replay
        # the same VCDParser multiple times and in non-monotonic order.
        # Object-level mutable state would leak future bit values into
        # earlier snapshots for bit-exploded buses.
        #
        # Laziness: when the caller selected a subset of signals (sids),
        # maintain only the synthesized bit-buses that can be emitted for
        # this query. This avoids touching large unrelated bit-exploded
        # buses during catch-up scans, while preserving exact behavior for
        # selected buses and for no-filter calls.
        if sids is None:
            bit_map = self._bit_map
            bit_state = {gid: bits[:] for gid, bits in self._bit_state_template.items()}
        else:
            bit_map = {}
            needed_gids = set()
            for sym0, refs in self._bit_map.items():
                kept = [(gid, idx) for gid, idx in refs if gid in sids]
                if kept:
                    bit_map[sym0] = kept
                    for gid, _idx in kept:
                        needed_gids.add(gid)
            bit_state = {gid: self._bit_state_template[gid][:] for gid in needed_gids}
        # A synthesized bus has no previous observation until at least one of
        # its bit identifiers occurs. The template's all-x value is not an
        # observation and must not suppress a first all-x record in the window.
        observed_bit_buses = set()

        def _next():
            nonlocal toks, ntoks, ti
            if pushback:
                return pushback.pop()
            while ti >= ntoks:
                nl = next(list_iter, None)
                if nl is None:
                    return None
                toks = nl
                ntoks = len(nl)
                ti = 0
            tok = toks[ti]
            ti += 1
            return tok

        try:
            while True:
                # Inline token fetch (hot path): a direct index read with no
                # function call for the common case; _next() is reserved for
                # the parser's b/r/p look-ahead and section skipping.
                if pushback:
                    tok = pushback.pop()
                elif ti < ntoks:
                    tok = toks[ti]
                    ti += 1
                else:
                    nl = next(list_iter, None)
                    if nl is None:
                        break
                    toks = nl
                    ntoks = len(nl)
                    tok = toks[0]
                    ti = 1

                c0 = tok[0]
                # Top-level $keyword. Known wrappers ($dumpvars etc) and a bare
                # $end are pass-through markers; any other $section's body is
                # dropped to its $end so '$bogus 1! $end' can't pollute the
                # waveform. Gating on the first character keeps non-$ tokens
                # (the overwhelming majority) out of these comparisons.
                if c0 == '$':
                    if tok == '$end' or tok in _SIM_KEYWORDS:
                        continue
                    while True:
                        t = _next()
                        if t is None or t == '$end':
                            break
                    continue

                if c0 == '#' and len(tok) > 1 and tok[1].isdigit():
                    new_t = _parse_vcd_timestamp_token(tok)
                    if new_t is None:
                        # Malformed (e.g. '#1.5'); silently skip per round-7 policy.
                        continue
                    if cur_t >= t0:
                        for sid, prev, val in _flush():
                            yield cur_t, sid, prev, val
                    elif new_t >= t0:
                        # Crossing into the window: hand bit-exploded buses the
                        # no-op baseline a full scan would have built. Joined
                        # once per bus here, not per catch-up record — doing it
                        # in the catch-up loop would make the head scan O(width)
                        # per bit change.
                        for gid in observed_bit_buses:
                            last_val[gid] = ''.join(reversed(bit_state[gid]))
                    cur_t = new_t
                    if t1 is not None and cur_t > t1:
                        return
                    continue

                # ---- Value change ----
                # The 1-bit scalar form (a single leading 0/1/x/z/X/Z followed
                # by the identifier_code) is by far the most common token, so it
                # is parsed inline here without a helper call. b/r/p forms keep
                # going through _consume_value_change so the malformed-token
                # validation rules live in exactly one place.
                if c0 in '01xXzZ' and len(tok) > 1:
                    sym = tok[1:]
                    # Fast-path filter: drop unneeded signals before any work.
                    if sids is not None and sym not in sids and sym not in bit_map:
                        continue
                    val = c0 if c0 in '01xz' else c0.lower()
                elif c0 in 'bBrRp':
                    # Fast-path filter peek for b/r (identifier is the next
                    # token). p is left to the standalone-stage filter, matching
                    # prior behavior.
                    if sids is not None and c0 in 'bBrR':
                        sym_tok = _next()
                        if sym_tok is not None and not self._is_structural_token(sym_tok):
                            if sym_tok not in sids and sym_tok not in bit_map:
                                continue  # consume both tokens, skip
                            pushback.append(sym_tok)  # needed — put back for parser
                        elif sym_tok is not None:
                            pushback.append(sym_tok)
                    parsed = self._consume_value_change(tok, _next, pushback)
                    if parsed is None:
                        continue
                    sym, val = parsed
                else:
                    # Not a value_change opener (e.g. stray '#', bare 'b').
                    continue

                # Catch-up before t0: don't emit, but DO advance last_val — the
                # no-op baseline. Without it a record at or after t0 that merely
                # re-asserts a pre-t0 value reads as a first observation, so
                # `dump --begin` reported changes a full scan suppressed. That
                # re-assertion is routine: iverilog's $dumpall checkpoint re-emits
                # every signal in dump scope.
                if cur_t < t0:
                    if sym in bit_map:
                        bit_val = val if len(val) == 1 and _is_4state_bits(val) else 'x'
                        for gid, idx in bit_map[sym]:
                            bit_state[gid][idx] = bit_val
                            observed_bit_buses.add(gid)
                    if sids is None or sym in sids:
                        info = signals.get(sym)
                        if info is not None:
                            w = vec_width.get(sym)
                            if w is not None and len(val) < w and _is_4state_bits(val):
                                val = val.rjust(w, _PAD_CHAR[val[0]])
                            elif len(val) > info['width']:
                                val = _clamp_overwide_logic_value(val, info)
                            last_val[sym] = val
                    continue

                # Bit-exploded signal: aggregate into virtual bus value(s).
                # If the same identifier_code drives multiple synthesized buses
                # (via aliased parent declarations), each gets its own event.
                #
                # IMPORTANT: do NOT continue after this branch. Per IEEE 1364-2005
                # 18.2.3.7, the same identifier_code can be referenced by both a
                # standalone $var (e.g. clk) AND a bit-select $var (e.g.
                # data_bus[0]) when RTL assigns one to the other. If we continued,
                # the standalone alias would silently never emit events and the
                # agent would see clk as a flat line. Fall through to the
                # standalone block so both signals update on the same value_change.
                if sym in bit_map:
                    bit_val = val if len(val) == 1 and _is_4state_bits(val) else 'x'
                    for gid, idx in bit_map[sym]:
                        if sids is None or gid in sids:
                            written = bus_dirty.get(gid)
                            if written is None:
                                bus_dirty[gid] = {idx}
                            elif idx in written:
                                if bit_state[gid][idx] != bit_val:
                                    _record(gid, ''.join(reversed(bit_state[gid])))
                                bus_dirty[gid] = {idx}
                            else:
                                written.add(idx)
                        bit_state[gid][idx] = bit_val

                # Standalone signal (may run after the bit-bus branch above when
                # the sym serves both roles).
                info = signals.get(sym)
                if info is None:
                    continue
                if sids is not None and sym not in sids:
                    continue
                # One width read covers every case. n == w is the overwhelming
                # majority (scalars, full-width vectors). Short logic-vector
                # values are left-extended to the declared width (see
                # _vec_width) so equal values share one spelling; real/event
                # values are never padded. Over-wide values go through the
                # clamp helper, the single source of truth for that rare case.
                n = len(val)
                w = info['width']
                if n == w:
                    _record(sym, val)
                elif n < w:
                    if sym in vec_width and _is_4state_bits(val):
                        val = val.rjust(w, _PAD_CHAR[val[0]])
                    _record(sym, val)
                else:
                    _record(sym, _clamp_overwide_logic_value(val, info))

            # Final flush
            if cur_t >= t0:
                for sid, prev, val in _flush():
                    yield cur_t, sid, prev, val
        finally:
            close = getattr(list_iter, 'close', None)
            if close is not None:
                close()

    def scan_time_range(self):
        """Min/max timestamps in the file.

        Both ends are found by a single FORWARD scanner, ``_scan_timestamps``,
        which replays iter_events()'s top-level grammar (see that method), so
        info's time range is derived by exactly the parser's rules:

        - **t_min**: forward scan from ``_data_offset`` — a real top-level sync
          point — stopping at the first top-level ``#T`` (typically within the
          first few KB). Value changes, or a ``$dumpvars`` block, before any
          ``#T`` yield t_min = 0.
        - **t_max**: the same forward scanner over a *small tail window* read
          from EOF, grown geometrically until a top-level ``#T`` is found. The
          last ``#T`` in file order is the last timestamp — matching
          iter_events()'s final ``cur_t`` (which ``_search_end_time`` relies on
          as the implicit search end). A legal VCD may carry an unbounded
          value_change run, or a large ``$dumpall`` checkpoint, after the final
          ``#T``; grow-on-miss covers that. A window that begins inside a
          section body is handled by the scanner's resync, and the final grow
          reaches the data-section floor — a provably-correct full forward scan
          that the old reverse walk never had.

        Reading only a bounded tail (``VCD_ANALYZER_TAIL_WINDOW``, default
        64 KiB, doubled on a miss) keeps ``info`` on a 500 MB VCD to well under
        a second instead of the ~90 s a full sequential scan would cost. All
        ``#T`` parsing routes through the hardened ``_parse_vcd_timestamp_token``
        (bounded digits, int64 cap), so a hostile timestamp yields a clean CLI
        error rather than a raw traceback.

        (Replaces a reverse tail walk that reconstructed VCD grammar backwards
        from an arbitrary offset — a recurring source of correctness bugs. The
        forward scanner is provably equal to the event stream; see
        ``_scan_timestamps``. The "any ``$X`` that is not ``$end``/``$dump*``" drain rule matches
        iter_events() exactly.)
        """
        # -- t_min: forward scan from the data-section start, stop at first #T --
        # Small lazy chunks (not iter_events' large read): _scan_timestamps
        # returns at the first top-level #T, so only the head is read. close()
        # releases the generator's file handle once we stop pulling from it.
        head = self._data_token_lists(chunk_size=64 * 1024)
        try:
            first_ts, saw_value, _ = self._scan_timestamps(head, stop_at_first=True)
        finally:
            head.close()
        t_min = 0 if saw_value else first_ts

        # -- t_max: forward scan over a bounded EOF tail window, grow on miss --
        # Forward scanning (not reverse grammar reconstruction) gives exact
        # parity with iter_events(). The small initial window keeps the common
        # case — the last #T sits a few KB before EOF — cheap; grow-on-miss
        # covers a large trailing value_change run or $dumpall checkpoint. Each
        # grow re-reads a strictly larger EOF window and rescans from scratch,
        # so no cross-window carry/skip state is needed.
        file_size = os.path.getsize(self.path)
        # _data_offset may be a text-mode tell() cookie (opaque, possibly larger
        # than file_size); clamp to a safe floor for the binary tail read.
        floor = self._data_offset if self._data_offset < file_size else 0
        window = _env_int('VCD_ANALYZER_TAIL_WINDOW', 64 * 1024)
        if window < 1:
            window = 1
        t_max = None
        while t_max is None:
            start = max(floor, file_size - window)
            with open(self.path, 'rb') as f:
                f.seek(start)
                data = f.read(file_size - start)
            if start > floor:
                # The low edge may cut a token; drop the leading partial
                # fragment. Safe: if it held the only #T this window "misses"
                # and the next (larger) window re-reads it intact.
                j = 0
                n = len(data)
                while j < n and data[j] not in _ASCII_WS_BYTES:
                    j += 1
                    if j > MAX_DATA_TOKEN_LEN:
                        raise _VCDResourceError('VCD token exceeds {} characters'.format(MAX_DATA_TOKEN_LEN))
                data = data[j:]
            toks = data.decode('ascii', errors='replace').split()
            _check_token_lengths(toks)
            _, _, last = self._scan_timestamps([toks], resync=(start > floor))
            if last is not None:
                t_max = last
                break
            if start <= floor:
                break            # whole data section scanned: no top-level #T
            window *= 2          # grow-on-miss
        if t_max is None:
            t_max = t_min
        if t_min is None:
            t_min = t_max
        return t_min, t_max

    def state_at(self, t_at, sids=None):
        """Settled signal state at t_at: {sig_id: value} for known signals.

        Last-write-wins fold of the change stream through t_at (inclusive).
        Only signals with an observed value appear; no unknowns are invented.
        This is the STATE@T view used by snapshot and as a baseline.
        """
        state = {}
        for _t, sid, val in self.iter_events(0, t_at, sids):
            state[sid] = val
        return state

    def state_before(self, t_at, sids=None):
        """Settled state strictly before t_at (exclusive).

        VCD timestamps are integer ticks, so the exclusive snapshot is the
        inclusive snapshot at t_at - 1; before t=0 there is no prior state.
        """
        if t_at <= 0:
            return {}
        return self.state_at(t_at - 1, sids)

    def state_pair(self, ta, tb, sids=None):
        """Settled state at ta and at tb in one pass (assumes ta <= tb).

        Returns (state_a, state_b), each {sig_id: value} = last value at or
        before the respective boundary (inclusive). Used by compare.
        """
        state = {}
        state_a = None
        for t, sid, val in self.iter_events(0, tb, sids):
            if state_a is None and t > ta:
                state_a = dict(state)
            state[sid] = val
        if state_a is None:
            state_a = dict(state)
        return state_a, dict(state)



