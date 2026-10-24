# ================================================================
# Part 5: Output helpers
# ================================================================


_DEFAULT_LIMIT = 500


class _ResultRows:
    """Disk-backed rows for unlimited output."""

    def __init__(self):
        self.file = tempfile.TemporaryFile(mode='w+t', encoding='utf-8')
        self.count = 0

    def append(self, row):
        self.file.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n')
        self.count += 1

    def __len__(self):
        return self.count

    def __iter__(self):
        self.file.seek(0)
        for line in self.file:
            yield json.loads(line)


def _json(obj):
    """Compact JSON for agent use."""
    if any(isinstance(value, _ResultRows) for value in obj.values()):
        write = sys.stdout.write
        write('{')
        for i, (key, value) in enumerate(obj.items()):
            write((',' if i else '') + json.dumps(key) + ':')
            if isinstance(value, _ResultRows):
                write('[')
                value.file.seek(0)
                for j, line in enumerate(value.file):
                    write((',' if j else '') + line.rstrip('\n'))
                write(']')
            else:
                write(json.dumps(value, ensure_ascii=False, separators=(',', ':')))
        write('}\n')
        return
    print(json.dumps(obj, ensure_ascii=False, separators=(',', ':')))


def _limit(args):
    """Resolve global output limit. --verbose disables truncation unless an
    explicit --limit was supplied. --limit 0 always means unlimited."""
    val = getattr(args, 'limit', None)
    if val is None:
        return 0 if getattr(args, 'verbose', False) else _DEFAULT_LIMIT
    if val < 0:
        raise _LimitParseError('limit must be non-negative; got {}'.format(val))
    return val


def _clip(seq, limit):
    if limit == 0:
        return seq, False
    return seq[:limit], len(seq) > limit


def _trunc_text(shown, total, noun, exact):
    """Clipped-result notice.

    Stands off by a blank line and leads with TRUNCATED, because the previous
    one-line '... truncated: 2/3 rows shown.' was easy to skim past — and it
    named neither of the flags that lift the cap.
    """
    return ('\n>> TRUNCATED: showing {} of {}{} {}. '
            'Raise the cap with --limit N, or --limit 0 for all.').format(
                shown, total, '' if exact else '+', noun)


def _trunc_line(shown, total, noun):
    return _trunc_text(shown, total, noun, True)


def _trunc_line_lower_bound(shown, total, noun):
    """Truncation line when scanning stopped at the first unshown result.

    Used by streaming commands where --limit is an execution bound, not just
    an output bound. `total` is a lower bound (normally shown + 1),
    not the exact global result count.
    """
    return _trunc_text(shown, total, noun, False)


def _trunc_hint(truncated, shown, total, exact, noun):
    """JSON `hint` field for a clipped result, and nothing for a complete one.

    `truncated: true` sitting among a dozen other keys is easy to skim past; a
    sentence naming the flag that lifts the cap is not. Appears only when
    something was clipped, so no existing key changed name, type, or meaning.
    """
    if not truncated:
        return {}
    return {'hint': 'showing {} of {}{} {}; raise the cap with --limit N, '
                    'or --limit 0 for all'.format(
                        shown, total, '' if exact else '+', noun)}


def _total_json_fields(total, truncated):
    """Return JSON count fields for exact vs early-stopped result sets.

    When truncated is true, total is only a lower bound (usually limit+1).
    Keeping it numeric is convenient for agents, while total_is_exact prevents
    consumers from treating it as the real global count.
    """
    return {'total': total, 'total_is_exact': not truncated}


def _count_label(shown, total, truncated):
    """Human count label for result headers."""
    return '{}+'.format(total) if truncated else str(total)


def _selected_sids(vcd, sids):
    """Return an explicit set of selected signal ids."""
    return set(vcd.signals.keys()) if sids is None else set(sids)


def _fmt_maybe(value, info):
    return fmt_val(value, info) if value is not None else '(undef)'


