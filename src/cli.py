# ================================================================
# Part 9: CLI entry
# ================================================================



def _add_time_args(sp):
    sp.add_argument('--begin', metavar='TIME',
                    help='start time, e.g. 0, 100ns, 17.5us (omit = from start)')
    sp.add_argument('--end', metavar='TIME',
                    help='end time, same format (omit = no upper bound)')


def _add_filter(sp):
    sp.add_argument('--filter', metavar='K1,K2,...',
                    type=_normalize_filter_patterns,
                    help='comma-separated substring/glob patterns, case-insensitive')


def _add_common(sp):
    # Also accept global-style output controls after the subcommand.
    # Defaults are SUPPRESS so values supplied before the subcommand survive.
    sp.add_argument('--json', action='store_true', default=argparse.SUPPRESS,
                    help='output compact structured JSON instead of text')
    sp.add_argument('--limit', type=int, default=argparse.SUPPRESS,
                    help='max rows/records to emit; default 500; 0 = unlimited; streaming commands stop after the first unshown result')
    sp.add_argument('--verbose', action='store_true', default=argparse.SUPPRESS,
                    help='show extra fields; if --limit is omitted, disables truncation')


def main():
    global _AUTO_SCRIPT_PATH
    _AUTO_SCRIPT_PATH = os.path.abspath(sys.argv[0])
    p = argparse.ArgumentParser(
        prog='vcd_analyzer',
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--json', action='store_true',
                   help='output compact structured JSON instead of text')
    p.add_argument('--limit', type=int, default=None,
                   help='max rows/records to emit; default 500; 0 = unlimited; streaming commands stop after the first unshown result')
    p.add_argument('--verbose', action='store_true',
                   help='show extra fields; if --limit is omitted, disables truncation')
    p.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    sub = p.add_subparsers(dest='cmd', metavar='<command>')

    sp = sub.add_parser('index', help='build the optional .vcidx sidecar for fast random access')
    sp.add_argument('file', metavar='<file>')
    sp.add_argument('--block-mib', type=int, default=8, metavar='N',
                    help='index block size in MiB, 1..4096 (default 8)')
    sp.add_argument('--force', action='store_true',
                    help='rebuild even if the sidecar already exists')
    sp.add_argument('--output', metavar='PATH', default=None,
                    help='write the sidecar at PATH and link <file>.vcidx to it')
    sp.add_argument('--auto', action='store_true', help=argparse.SUPPRESS)
    _add_common(sp)

    sp = sub.add_parser('info', help='file overview: timescale, signal count, time span, scopes')
    sp.add_argument('file', metavar='<file>', help='VCD file path'); _add_common(sp)

    sp = sub.add_parser('list', help='list signals with path and bit width')
    sp.add_argument('file', metavar='<file>'); _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('dump', help='print value-change events in time order')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('summary', help='window stats: active/static/undefined selected signals')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('snapshot', help='known signal values at a given time point')
    sp.add_argument('file', metavar='<file>')
    sp.add_argument('--at', metavar='TIME', required=True, help='time point, e.g. 17.55us')
    _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('compare', help='diff known signal values between two time points')
    sp.add_argument('file', metavar='<file>')
    sp.add_argument('--at', metavar='T1,T2', required=True, help='two time points comma-separated, e.g. 17.5us,17.7us')
    _add_filter(sp); _add_common(sp)

    sp = sub.add_parser('search', help='conditional search and associated signal observation')
    sp.add_argument('file', metavar='<file>'); _add_time_args(sp); _add_common(sp)
    sp.add_argument('--condition', metavar='COND', required=True, action='append',
                    help='comma-separated AND terms: SIG=VAL, SIG!=VAL, or changed(SIG); '
                         '!= does not match x/z/undef. Repeat the flag to OR the clauses '
                         '(there is no in-string OR). A changed(SIG) term switches to event '
                         'mode; then every clause must carry one')
    sp.add_argument('--show', metavar='PAT1,PAT2,...', type=_normalize_filter_patterns,
                    help='signals to display while the condition holds; output segments split when shown values change')
    sp.add_argument('--changed', metavar='PATTERN', default=None,
                    help=argparse.SUPPRESS)

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        sys.exit(1)
    block_mib = getattr(args, 'block_mib', None)
    if block_mib is not None and not 1 <= block_mib <= 4096:
        sys.exit('Error: --block-mib must be between 1 and 4096')
    if getattr(args, 'changed', None) is not None:
        # Removed in 1.5.0: the flag's event mode was a variant of --condition
        # wearing a flag's clothes, and being a flag it applied to the whole
        # query — an edge could not be scoped to one OR clause, and two signals
        # could not be required to transition together.
        sys.exit('Error: --changed was removed; write the edge as a condition term instead: '
                 '--condition "changed({})"'.format(args.changed))

    try:
        cmds = {'info': cmd_info, 'list': cmd_list, 'dump': cmd_dump, 'summary': cmd_summary,
                'snapshot': cmd_snapshot, 'compare': cmd_compare, 'search': cmd_search,
                'index': cmd_index}
        # The index only accelerates reads; a missing/stale/rejected
        # sidecar silently keeps the plain parser (one warning at most).
        vcd = try_index(args.file) or VCDParser(args.file)
        if args.cmd != 'index':
            maybe_auto_build(vcd, args.file)
        try:
            if vcd.timescale_warning:
                try:
                    sys.stderr.write('Warning: {}\n'.format(vcd.timescale_warning))
                except (OSError, ValueError):
                    pass
            cmds[args.cmd](vcd, args)
        finally:
            close = getattr(vcd, 'close', None)
            if close is not None:
                close()
    except FileNotFoundError as e:
        sys.exit('Error: cannot open VCD file: {}'.format(e.filename or args.file))
    except IsADirectoryError as e:
        sys.exit('Error: not a file: {}'.format(e.filename or args.file))
    except PermissionError as e:
        sys.exit('Error: permission denied: {}'.format(e.filename or args.file))
    except BrokenPipeError:
        raise
    except OSError as e:
        sys.exit('Error: ' + str(e))
    except _TimeParseError as e:
        sys.exit('Error: ' + str(e))
    except _LimitParseError as e:
        sys.exit('Error: ' + str(e))
    except _ValueParseError as e:
        sys.exit('Error: ' + str(e))
    except _ConditionParseError as e:
        sys.exit('Error: ' + str(e))
    except _VCDResourceError as e:
        sys.exit('Error: ' + str(e))
    except _FilterParseError as e:
        # Reaches here only if raised from VCDParser.match() at runtime;
        # argparse handles the same error when raised from type=.
        sys.exit('Error: ' + str(e))


if __name__ == '__main__':
    import signal as _sig
    if hasattr(_sig, 'SIGPIPE'):
        _sig.signal(_sig.SIGPIPE, _sig.SIG_DFL)
    # Verbatim VCD text and ensure_ascii=False JSON can carry non-ASCII
    # characters (signal paths, $version/$date strings). Force UTF-8 so a
    # legacy Windows codepage cannot turn a valid dump into a
    # UnicodeEncodeError. No-op where reconfigure() is unavailable.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, ValueError, OSError):
            pass
    try:
        main()
    except KeyboardInterrupt:
        # Conventional 128 + SIGINT(2): a clean exit, no traceback.
        sys.exit(130)
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        sys.exit(0)
