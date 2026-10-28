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


# -- where results go -----------------------------------------------------
#
# A query writes its result to stdout. Three destinations, three policies:
#   * --output FILE: the whole result goes to FILE (published atomically),
#     stdout gets a one-line receipt — the way to keep an unlimited dump.
#   * a pipe or a redirect: everything is streamed; the caller chose where
#     it goes (| grep, | less, > file).
#   * an interactive terminal: output stops after _TERMINAL_BUDGET with a
#     notice. A `--limit 0 dump` of a big dump is hundreds of MB that
#     nobody reads on a terminal and that takes minutes to scroll past.

_TERMINAL_BUDGET = 1 << 20


class _OutputPathError(Exception):
    """--output cannot be written (reported as a CLI error, not as an
    unreadable VCD)."""


class _OutputBudgetExceeded(Exception):
    """Raised through the command when the terminal budget is spent."""


class _TerminalBudget:
    """stdout proxy for an interactive terminal: passes text through until
    _TERMINAL_BUDGET characters, ends on the last whole line within it,
    then stops the command. (print() writes a line and its newline
    separately, so a write may hold no newline at all; the cut then falls
    after the previous write. Only output that has no line break within the
    whole budget — one huge JSON line — is shown cut mid-line.)"""

    def __init__(self, stream, budget):
        self._stream = stream
        self._budget = self._left = budget

    def write(self, text):
        if len(text) <= self._left:
            self._left -= len(text)
            return self._stream.write(text)
        head = text[:self._left]
        cut = head.rfind('\n')
        if cut >= 0:
            self._stream.write(head[:cut + 1])
        elif self._left == self._budget:
            self._stream.write(head)
        self._left = 0
        raise _OutputBudgetExceeded()

    def __getattr__(self, name):
        return getattr(self._stream, name)


class _CountingSink:
    """File proxy that counts the lines written through it."""

    def __init__(self, stream):
        self._stream = stream
        self.lines = 0

    def write(self, text):
        self.lines += text.count('\n')
        return self._stream.write(text)

    def __getattr__(self, name):
        return getattr(self._stream, name)


def _is_terminal(stream):
    try:
        return stream.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def _run_command(command, vcd, args):
    """Run a query command against the destination its output should go to."""
    target = getattr(args, 'output_file', None)
    if target:
        return _run_to_file(command, vcd, args, target)
    stdout = sys.stdout
    if not _is_terminal(stdout):
        return command(vcd, args)
    sys.stdout = _TerminalBudget(stdout, _TERMINAL_BUDGET)
    try:
        command(vcd, args)
    except _OutputBudgetExceeded:
        sys.stdout = stdout
        stdout.flush()
        sys.stderr.write(
            '\n>> OUTPUT CUT: {} MiB shown on the terminal. Write the whole result to a file '
            'with --output FILE, or pipe it (| less, | grep, > file).\n'.format(
                _TERMINAL_BUDGET >> 20))
    finally:
        sys.stdout = stdout


def _run_to_file(command, vcd, args, target):
    """Write the command's stdout to target (via a temp file in the same
    directory, renamed on success), then print a receipt on stdout."""
    target = os.path.abspath(target)
    source = os.path.abspath(args.file)
    if os.path.realpath(target) == os.path.realpath(source) or (
            os.path.exists(target) and os.path.samefile(target, source)):
        raise _OutputPathError('--output must not be the VCD file itself')
    # Created like a shell redirect would (mode 0666 minus the umask), not
    # with mkstemp's private 0600: the result is the user's file.
    temp = '{}.{}.part'.format(target, os.getpid())
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    except OSError as error:
        raise _OutputPathError('cannot write --output {}: {}'.format(
            target, error.strerror or error))
    stdout = sys.stdout
    published = False
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as sink:
            counted = _CountingSink(sink)
            sys.stdout = counted
            try:
                command(vcd, args)
            except SystemExit as stop:
                if stop.code not in (None, 0):
                    raise
            finally:
                sys.stdout = stdout
        os.replace(temp, target)
        published = True
    finally:
        if not published:
            try:
                os.unlink(temp)
            except OSError:
                pass
    size = os.path.getsize(target)
    if getattr(args, 'json', False):
        print(json.dumps({'output': target, 'bytes': size, 'lines': counted.lines},
                         ensure_ascii=False, separators=(',', ':')))
    else:
        print('Wrote {:,} lines ({:,} bytes) to {}'.format(counted.lines, size, target))


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


