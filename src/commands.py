# ================================================================
# Part 8: Commands
# ================================================================

def cmd_index(vcd, args):
    """Build the optional .vcidx sidecar for fast random access.

    Explicit by design for interactive use: queries never write (the
    background auto-builder is the one exception, gated by its own lock).
    --output stores the sidecar at PATH and links <file>.vcidx to it so
    queries still find it; a failed link is reported, never fatal. The
    full variant builds via its embedded native library when one serves
    the platform, else the pure-Python pass (identical sidecar semantics).
    """
    sidecar = sidecar_path(args.file)
    target = os.path.abspath(args.output) if args.output else sidecar
    if args.output:
        # Sidecars are always named *.vcidx — an arbitrary extension would
        # leave unrecognizable binary files on disk and invite confusion
        # with the waveform itself.
        if not target.endswith('.vcidx'):
            sys.exit('Error: --output must end with .vcidx '
                     '(e.g. --output {}{})'.format(target, '.vcidx'))
        # --output pointing at the input VCD would REPLACE the waveform
        # with the sidecar at publication; --force must not bypass this.
        same = (os.path.realpath(target) == os.path.realpath(args.file)
                or (os.path.exists(target)
                    and os.path.exists(args.file)
                    and os.path.samefile(target, args.file)))
        if same:
            sys.exit('Error: --output must not be the VCD file itself')
    auto = bool(getattr(args, 'auto', False))
    lock_fd = None
    if auto:
        # The background builder holds the OS lock for its own lifetime.
        # A lost race (another builder grabbed it) exits quietly.
        lock_fd = _acquire_build_lock(sidecar)
        if lock_fd is None:
            sys.exit(0)
    try:
        if os.path.exists(target) and not (args.force or auto):
            sys.exit('Error: {} already exists; use --force to rebuild'.format(target))
        block_bytes = args.block_mib << 20
        try:
            stats = build_index_best(args.file, target, block_bytes,
                                     threads=getattr(args, 'threads', None))
        except (ValueError, _VCDResourceError, struct.error, KeyError) as error:
            # Builders publish atomically and clean their OWN temp files;
            # a failed rebuild must leave a pre-existing target untouched.
            sys.exit('Error: cannot index {}: {}'.format(args.file, error))
        if args.output:
            _link_sidecar(sidecar, target)
    finally:
        if lock_fd is not None:
            os.close(lock_fd)  # releases the OS lock; the file is kept
    builder = stats.get('builder', 'python')
    r = {'file': args.file, 'sidecar': sidecar,
         'builder': builder,
         'build_s': round(stats.get('build_s', 0.0), 3),
         'source_bytes': stats.get('source_bytes'),
         'index_bytes': stats.get('index_bytes'),
         'index_pct': round(100.0 * stats.get('index_bytes', 0)
                            / max(1, stats.get('source_bytes', 1)), 4),
         'blocks': stats.get('blocks'),
         'raw_symbols': stats.get('raw_symbols'),
         'signal_block_pairs': stats.get('signal_block_pairs'),
         'threads': stats.get('threads', 1)}
    if args.json:
        if builder == 'python' and r['source_bytes'] >= 64 << 20:
            _warn('index built with the slower pure-Python mechanism '
                  '(no native builder for this platform)', cat='index_slow_build')
        _json(r)
        return
    print('Built    : {}'.format(target))
    print('Builder  : {}'.format(builder))
    print('Source   : {:,} bytes'.format(r['source_bytes']))
    print('Index    : {:,} bytes ({:.4f}%)'.format(r['index_bytes'], r['index_pct']))
    print('Blocks   : {} x {} MiB'.format(r['blocks'], args.block_mib))
    print('Symbols  : {} raw, {:,} signal-block pairs'.format(
        r['raw_symbols'], r['signal_block_pairs']))
    print('Time     : {:.3f}s'.format(r['build_s']))
    if builder == 'python' and r['source_bytes'] >= 64 << 20:
        # Full variant, no library for this platform: say so when the file
        # is big enough for the difference to matter.
        print('Note     : no native builder for this platform — building with '
              'the pure-Python index mechanism (much slower). Supported '
              'platforms build natively with up to 4 threads.')
    print('Use      : queries pick this up automatically; VCD_ANALYZER_NO_INDEX=1 disables')


def cmd_info(vcd, args):
    _limit(args)
    t_min, t_max = vcd.scan_time_range()
    ts = vcd.ts_sec
    synth = [s for s in vcd.signals.values() if s.get('synthesized')]
    r = {
        'file': vcd.path,
        'size_bytes': os.path.getsize(vcd.path),
        'timescale': vcd.ts_str.replace('$timescale', '').replace('$end', '').strip(),
        # Provenance metadata from VCD header (IEEE 1364-2005 18.2.3.1-3).
        # Tells the agent which simulator produced the file and when, so
        # downstream debug can apply tool-specific heuristics (e.g. QuestaSim
        # bit-explodes wide buses but iverilog doesn't).
        'date': vcd.date,
        'version': vcd.version,
        'comments': list(vcd.comments),
        'signal_count': len(vcd.signals),
        'reference_count': vcd.raw_var_count,
        'synthesized_buses': len(synth),
        'var_types': dict(sorted(vcd.raw_type_counts.items(), key=lambda x: -x[1])),
        'time_min': fmt_time(t_min, ts) if t_min is not None else None,
        'time_min_ticks': t_min,
        'time_min_h': fmt_time(t_min, ts) if t_min is not None else None,
        'time_max': fmt_time(t_max, ts) if t_max is not None else None,
        'time_max_ticks': t_max,
        'time_max_h': fmt_time(t_max, ts) if t_max is not None else None,
        'duration': fmt_time(t_max - t_min, ts) if t_min is not None and t_max is not None else None,
        'duration_ticks': (t_max - t_min) if t_min is not None and t_max is not None else None,
        'duration_h': fmt_time(t_max - t_min, ts) if t_min is not None and t_max is not None else None,
        # Use declaration-time scope metadata instead of splitting public
        # paths on '.'. Escaped identifiers may legally contain dots;
        # path.split('.') would invent fake hierarchy such as tb.\foo.
        'scopes': sorted(set(
            sc for v in vcd.signals.values() for sc in v.get('scopes', []) if sc
        )),
    }
    if args.json:
        _json(r)
    else:
        print('File      : {}'.format(r['file']))
        print('Size      : {:,} bytes'.format(r['size_bytes']))
        if r['date']:
            print('Date      : {}'.format(r['date']))
        if r['version']:
            print('Tool      : {}'.format(r['version']))
        print('Timescale : {}'.format(r['timescale']))
        if r['signal_count'] == r['reference_count']:
            print('Signals   : {}'.format(r['signal_count']))
        elif r['synthesized_buses']:
            print('Signals   : {} ({} $var decls, {} reassembled as bit-buses)'.format(
                r['signal_count'], r['reference_count'], r['synthesized_buses']))
        else:
            print('Signals   : {} unique ({} $var refs via aliases)'.format(
                r['signal_count'], r['reference_count']))
        print('Types     : {}'.format(', '.join('{}={}'.format(k, v) for k, v in r['var_types'].items())))
        if r['time_min'] is None:
            print('Time      : (no data in file)')
        else:
            print('Time      : {} ~ {} ({})'.format(r['time_min'], r['time_max'], r['duration']))
        for s in r['scopes']:
            print('  scope: {}'.format(s))
        if r['comments'] and getattr(args, 'verbose', False):
            # Comments verbose-only: typical files have boilerplate
            # ("Generated by ..."), worth showing only on demand.
            print('Comments  :')
            for c in r['comments']:
                print('  - {}'.format(c))


def cmd_list(vcd, args):
    limit = _limit(args)
    sids = vcd.match(args.filter)
    entries = []
    for sid, info in vcd.signals.items():
        if sids is not None and sid not in sids:
            continue
        vtype = info.get('type', 'wire')
        for path in info['aliases']:
            e = {'path': path, 'width': info['width'], 'type': vtype}
            if getattr(args, 'verbose', False):
                e['id'] = sid
                if info.get('synthesized'):
                    e['synthesized'] = True
                    e['raw_bits'] = info.get('raw_bits')
            entries.append(e)
    entries.sort(key=lambda e: e['path'])
    aliases_total = sum(len(info['aliases']) for info in vcd.signals.values())
    shown, trunc = _clip(entries, limit)
    if args.json:
        _json({'total': len(entries), 'aliases_total': aliases_total,
               'shown': len(shown), 'truncated': trunc,
               **_trunc_hint(trunc, len(shown), len(entries), True, 'signals'),
               'signals': shown})
    else:
        # Numerator and denominator both count alias paths in the signal view
        # (one row per alias, so a signal with two aliases reads "Matched: 2/2",
        # not "2/1"): the matched aliases out of all signal aliases.
        print('Matched: {}/{}'.format(len(entries), aliases_total))
        for e in shown:
            print('  {:<60} {:>5}  {}'.format(e['path'], e['width'], e['type']))
        if trunc:
            print(_trunc_line(len(shown), len(entries), 'signals'))


def cmd_dump(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1 = parse_time(args.end, ts) if args.end else None
    if t1 is not None and t1 < t0:
        raise _TimeParseError('end time must be >= begin time')
    sids = vcd.match(args.filter)
    limit = _limit(args)
    verbose = getattr(args, 'verbose', False)
    # Many value_changes share one timestamp, so memoize the formatted time
    # across consecutive events. fmt_time() depends only on (t, ts), so this
    # stays output-identical while collapsing ~one fmt_time call per timestamp
    # instead of one per event.

    if args.json:
        total = 0
        truncated = False
        events = _ResultRows() if limit == 0 else []
        last_t = object()
        last_th = None
        for t, sid, val in vcd.iter_events(t0, t1, sids):
            total += 1
            if limit != 0 and len(events) >= limit:
                truncated = True
                break
            info = vcd.signals[sid]
            if t != last_t:
                last_t = t
                last_th = fmt_time(t, ts)
            e = {'time': t, 'time_ticks': t, 'time_h': last_th,
                 'path': info['path'], 'value': fmt_val(val, info)}
            if verbose:
                e['width'] = info['width']
                e['type'] = info.get('type', 'wire')
            events.append(e)
        obj = {'shown': len(events), 'truncated': truncated,
               **_trunc_hint(truncated, len(events), total, False, 'events'),
               'events': events}
        obj.update(_total_json_fields(total, truncated))
        _json(obj)
        return

    # Text output streams straight to stdout: no per-event dict is built, and
    # lines are flushed in batches rather than one print() per line. On a dump
    # of millions of events this removes the intermediate list and most of the
    # write-call overhead. The emitted bytes are identical to the prior
    # two-pass implementation.
    write = sys.stdout.write
    buf = []
    buf_append = buf.append
    shown = 0
    total = 0
    truncated = False
    # One memoized sentinel drives both the T= header and the formatted time:
    # last_t and cur always changed on the same events.
    cur = object()
    last_th = None
    for t, sid, val in vcd.iter_events(t0, t1, sids):
        total += 1
        if limit != 0 and shown >= limit:
            truncated = True
            break
        info = vcd.signals[sid]
        if t != cur:
            cur = t
            last_th = fmt_time(t, ts)
            buf_append('T={}\n'.format(last_th))
        if verbose:
            buf_append('  {:<55} w={} {} = {}\n'.format(
                info['path'], info['width'], info.get('type', 'wire'), fmt_val(val, info)))
        else:
            buf_append('  {:<55} = {}\n'.format(info['path'], fmt_val(val, info)))
        shown += 1
        if len(buf) >= 8192:
            write(''.join(buf))
            buf.clear()
    if shown == 0:
        print('(no changes in range)')
        return
    if buf:
        write(''.join(buf))
    if truncated:
        print(_trunc_line_lower_bound(shown, total, 'events'))


def cmd_summary(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1 = parse_time(args.end, ts) if args.end else None
    if t1 is not None and t1 < t0:
        raise _TimeParseError('end time must be >= begin time')
    sids = vcd.match(args.filter)
    selected = _selected_sids(vcd, sids)
    rows, undef_sids, counts = _summary_rows(vcd, t0, t1, selected)
    active = [r for r in rows if r['kind'] == 'active']
    static = [r for r in rows if r['kind'] == 'static']
    ordered = active + static
    if getattr(args, 'verbose', False):
        for sid in undef_sids:
            info = vcd.signals[sid]
            ordered.append({'kind': 'undefined', 'path': info['path'], 'value': None,
                            'changes': 0, 'rise_count': 0 if info['width'] == 1 else None,
                            'fall_count': 0 if info['width'] == 1 else None,
                            'init': '(undef)', 'last': '(undef)',
                            '_width': info['width'], '_type': info.get('type', 'wire')})
    limit = _limit(args)
    shown, trunc = _clip(ordered, limit)
    begin_h = fmt_time(t0, ts)
    end_h = fmt_time(t1, ts) if t1 is not None else None
    if args.json:
        _json({'window': {'begin': begin_h, 'end': end_h,
                          'begin_ticks': t0, 'begin_h': begin_h,
                          'end_ticks': t1, 'end_h': end_h}, **counts,
               'shown': len(shown), 'truncated': trunc,
               **_trunc_hint(trunc, len(shown), len(ordered), True, 'rows'),
               'rows': [_public_row(r, getattr(args, 'verbose', False)) for r in shown]})
        return
    print('Window: {}..{}'.format(begin_h, end_h if end_h is not None else '(end)'))
    print('Selected: {}, Defined: {}, Undefined: {}'.format(
        counts['selected'], counts['defined'], counts['undefined']))
    print('Active: {}, Static: {}'.format(counts['active'], counts['static']))
    current = None
    for r in shown:
        dfn = ' defined@{}'.format(r['defined_at_h']) if 'defined_at_h' in r else ''
        if r['kind'] != current:
            current = r['kind']
            print('\n{}'.format(current.upper()))
        if r['kind'] == 'active':
            if getattr(args, 'verbose', False):
                edge = '' if r.get('rise_count') is None else ' r={} f={}'.format(
                    r.get('rise_count', 0), r.get('fall_count', 0))
                uniq = str(r.get('unique', 0))
                if not r.get('unique_is_exact', True):
                    uniq += '+'
                print('  {:<45} w={} {} chg={}{} init={} last={} first@{} last@{} uniq={}{}'.format(
                    r['path'], r['_width'], r['_type'], r['changes'], edge, r['init'], r['last'],
                    r.get('first_at', '-'), r.get('last_at', '-'), uniq, dfn))
            else:
                edge = '' if r.get('rise_count') is None else ' r={} f={}'.format(
                    r.get('rise_count', 0), r.get('fall_count', 0))
                print('  {:<45} chg={}{} init={} last={}{}'.format(
                    r['path'], r['changes'], edge, r['init'], r['last'], dfn))
        elif r['kind'] == 'static':
            if getattr(args, 'verbose', False):
                print('  {:<45} w={} {} value={}{}'.format(
                    r['path'], r['_width'], r['_type'], r['value'], dfn))
            else:
                print('  {:<45} value={}{}'.format(r['path'], r['value'], dfn))
        else:
            print('  {:<45} w={} {}'.format(r['path'], r['_width'], r['_type']))
    if not rows and not undef_sids:
        print('(no selected signals)')
    if trunc:
        print(_trunc_line(len(shown), len(ordered), 'rows'))


def cmd_snapshot(vcd, args):
    ts = vcd.ts_sec
    t_at = parse_time(args.at, ts)
    sids0 = vcd.match(args.filter)
    selected = _selected_sids(vcd, sids0)
    state = vcd.state_at(t_at, selected)
    rows = []
    for sid in sorted(state, key=lambda s: vcd.signals[s]['path']):
        info = vcd.signals[sid]
        r = {'path': info['path'], 'value': fmt_val(state[sid], info)}
        if getattr(args, 'verbose', False):
            r['width'] = info['width']
            r['type'] = info.get('type', 'wire')
        rows.append(r)
    undef = sorted(selected - set(state), key=lambda s: vcd.signals[s]['path'])
    if getattr(args, 'verbose', False):
        for sid in undef:
            info = vcd.signals[sid]
            rows.append({'path': info['path'], 'value': None, 'undefined': True,
                         'width': info['width'], 'type': info.get('type', 'wire')})
    limit = _limit(args)
    shown, trunc = _clip(rows, limit)
    if args.json:
        _json({'at': fmt_time(t_at, ts), 'at_ticks': t_at, 'at_h': fmt_time(t_at, ts),
               'selected': len(selected), 'known': len(state),
               'undefined': len(undef), 'shown': len(shown), 'truncated': trunc,
               **_trunc_hint(trunc, len(shown), len(rows), True, 'signals'),
               'signals': shown})
        return
    if not state:
        print('No known values at {}.'.format(fmt_time(t_at, ts)))
    else:
        print('Known snapshot @ {}'.format(fmt_time(t_at, ts)))
    if getattr(args, 'verbose', False):
        print('Selected: {}, Known: {}, Undefined: {}'.format(len(selected), len(state), len(undef)))
    for r in shown:
        if r.get('undefined'):
            print('  {:<55} = (undef)'.format(r['path']))
        elif getattr(args, 'verbose', False):
            print('  {:<55} w={} {} = {}'.format(r['path'], r.get('width'), r.get('type'), r['value']))
        else:
            print('  {:<55} = {}'.format(r['path'], r['value']))
    if trunc:
        print(_trunc_line(len(shown), len(rows), 'signals'))


def cmd_compare(vcd, args):
    ts = vcd.ts_sec
    parts = args.at.split(',')
    if len(parts) != 2:
        raise _TimeParseError(
            '--at needs two times separated by comma, e.g. --at 17.5us,17.7us')
    ta, tb = parse_time(parts[0].strip(), ts), parse_time(parts[1].strip(), ts)
    if tb < ta:
        raise _TimeParseError('second compare time must be >= first compare time')
    sids = vcd.match(args.filter)
    sa, sb = vcd.state_pair(ta, tb, sids)
    diffs = []
    for sid in sorted(set(sa) | set(sb), key=lambda s: vcd.signals[s]['path']):
        va, vb = sa.get(sid), sb.get(sid)
        if va != vb:
            info = vcd.signals[sid]
            d = {'path': info['path'],
                 'at_t1': fmt_val(va, info) if va is not None else '(undef)',
                 'at_t2': fmt_val(vb, info) if vb is not None else '(undef)'}
            if getattr(args, 'verbose', False):
                d['width'] = info['width']
                d['type'] = info.get('type', 'wire')
            diffs.append(d)
    limit = _limit(args)
    shown, trunc = _clip(diffs, limit)
    if args.json:
        _json({'t1': fmt_time(ta, ts), 't1_ticks': ta, 't1_h': fmt_time(ta, ts),
               't2': fmt_time(tb, ts), 't2_ticks': tb, 't2_h': fmt_time(tb, ts),
               'total': len(diffs), 'shown': len(shown), 'truncated': trunc,
               **_trunc_hint(trunc, len(shown), len(diffs), True, 'diffs'),
               'diffs': shown})
    else:
        print('Compare: {} vs {}'.format(fmt_time(ta, ts), fmt_time(tb, ts)))
        print('{} changed, {} unchanged'.format(len(diffs), len(set(sa) | set(sb)) - len(diffs)))
        for d in shown:
            print('  {:<48} {} -> {}'.format(d['path'], d['at_t1'], d['at_t2']))
        if trunc:
            print(_trunc_line(len(shown), len(diffs), 'diffs'))


def cmd_search(vcd, args):
    ts = vcd.ts_sec
    t0 = parse_time(args.begin, ts) if args.begin else 0
    t1_raw = parse_time(args.end, ts) if args.end else None
    t1 = _search_end_time(vcd, t0, t1_raw)
    if t1 < t0:
        if t1_raw is None:
            # No --end was given, so t1 is the file's last timestamp. A --begin
            # past it is an empty range, not an end-before-begin ordering error;
            # say so instead of blaming an --end the user never supplied.
            raise _TimeParseError(
                'begin time {} is after the last event at {}; nothing to search'.format(
                    fmt_time(t0, ts), fmt_time(t1, ts)))
        raise _TimeParseError('end time must be >= begin time')

    clauses = _resolve_clauses(vcd, args.condition)

    # Mode split: a clause carrying a changed() term describes ticks (event
    # mode); one without describes spans (interval/segment mode). The two row
    # shapes cannot merge, so mixing is a usage error rather than a silent
    # pick of one.
    with_changed = [cl for cl in clauses
                    if any(c['kind'] == 'changed' for c in cl)]
    if with_changed and len(with_changed) < len(clauses):
        raise _ConditionParseError(
            'cannot mix changed() and level-only --condition clauses: a changed() '
            'clause fires at ticks (event mode) while a level-only clause spans '
            'time (interval mode); give every clause a changed() term, or run two '
            'searches')
    event_mode = bool(with_changed)
    changed_sids = sorted(
        {c['sid'] for cl in clauses for c in cl if c['kind'] == 'changed'},
        key=lambda sid: vcd.signals[sid]['path'])

    show_sids = _resolve_show_sids(vcd, args.show)
    if event_mode and not show_sids:
        # Event mode with no --show: watch the changed() signals themselves.
        show_sids = list(changed_sids)

    # Cost scales with the distinct signals referenced, not the clause count.
    selected = set(c['sid'] for cl in clauses for c in cl)
    selected.update(show_sids)

    limit = _limit(args)
    verbose = getattr(args, 'verbose', False)
    cond_label = _join_clauses(clauses, _condition_label)
    cond_text = _join_clauses(clauses, _condition_result_text)

    if event_mode:
        # Event mode is a per-TICK query with per-RECORD emission.
        #
        # Per tick: collect the tick's genuine transitions, apply every record,
        # then judge the clauses. Every signal EXCEPT the one transitioning is
        # read at the tick's SETTLED state, which is what makes the answer
        # independent of the order records happen to be written in — IEEE 1364
        # fixes neither the order nor the count of value_changes within one
        # simulation_time, so a level term decided halfway through a tick was
        # reading an artifact of the writer. The transitioning signal is read
        # at the value it took AT that edge, since the order of one signal's
        # own records is the delta-cycle sequence and does carry meaning; that
        # is what keeps `changed(s),s=1` meaning "rising edge of s".
        #
        # Emission is per-record, so an event variable still counts each
        # trigger and an intra-tick 0->1->0 run still exposes each transition
        # (the 1.3.20 contract, and what `dump` shows). A clause requiring
        # SEVERAL signals to transition together is the exception: coincidence
        # is a property of the tick, not of any one record, so such a clause
        # reports the tick once.
        state = {}
        events = _ResultRows() if limit == 0 else []
        total = 0
        truncated = False
        changed_set = set(changed_sids)
        multi_clauses = []      # clauses requiring several signals to coincide
        by_edge_sid = {}        # sid -> single-edge clauses that sid can fire
        for cl in clauses:
            edge_sids = [c['sid'] for c in cl if c['kind'] == 'changed']
            if len(edge_sids) > 1:
                multi_clauses.append(cl)
            else:
                by_edge_sid.setdefault(edge_sids[0], []).append(cl)

        stop = False
        for gt, group in _transition_groups(vcd, 0, t1, selected):
            if gt < t0:
                # Baseline: settled state strictly before t0. Event mode reports
                # changes within [t0, t1], so a change landing exactly at t0 is
                # in-window — this `< t0` deliberately differs from interval
                # mode's `<= t0` (level semantics) below; do not unify.
                for gsid, _gprev, gval, _gkind in group:
                    state[gsid] = gval
                continue

            # A change is an event-var trigger (every record counts) or a real
            # value transition; a first observation (prev is None) is not a
            # change, matching the pre-1.3.20 contract.
            tick_changed = set()
            edges = []
            for gsid, gprev, gval, gkind in group:
                if gkind == 'event' or (gprev is not None and gprev != gval):
                    tick_changed.add(gsid)
                    if gsid in changed_set:
                        edges.append((gsid, gval))
                state[gsid] = gval
            if not edges:
                continue

            fired = []      # (ov_sid, ov_val) per emitted row
            for esid, edge_val in edges:
                for cl in by_edge_sid.get(esid, ()):
                    if _conditions_hold(state, cl, tick_changed, esid, edge_val):
                        fired.append((esid, edge_val))
                        break
            for cl in multi_clauses:
                if not _conditions_hold(state, cl, tick_changed):
                    continue
                edge_sids = {c['sid'] for c in cl if c['kind'] == 'changed'}
                if not any(sid in edge_sids and
                           _conditions_hold(state, cl, tick_changed, sid, val)
                           for sid, val in fired):
                    fired.insert(0, (None, None))
                    break
            for ov_sid, ov_val in fired:
                total += 1
                if limit != 0 and len(events) >= limit:
                    truncated = True
                    stop = True
                    break
                values, meta = _show_values(vcd, state, show_sids, verbose,
                                            ov_sid, ov_val)
                event = {'time_ticks': gt, 'time_h': fmt_time(gt, ts),
                         'values': values}
                if verbose:
                    event['meta'] = meta
                events.append(event)
            if stop:
                break

        if args.json:
            obj = {'mode': 'event', 'condition': cond_label,
                   'condition_resolved': cond_text,
                   'changed': [vcd.signals[sid]['path'] for sid in changed_sids],
                   'show': [vcd.signals[sid]['path'] for sid in show_sids],
                   'begin_ticks': t0, 'begin_h': fmt_time(t0, ts),
                   'end_ticks': t1, 'end_h': fmt_time(t1, ts),
                   'shown': len(events), 'truncated': truncated,
                   'events': events}
            obj.update(_trunc_hint(truncated, len(events), total, False, 'events'))
            obj.update(_total_json_fields(total, truncated))
            _json(obj)
            return
        if events:
            print('Found: {} event(s)'.format(_count_label(len(events), total, truncated)))
            for e in events:
                print('  T={:<12} {}'.format(e['time_h'], _values_text(e['values'])))
            if truncated:
                print(_trunc_line_lower_bound(len(events), total, 'events'))
        else:
            print('No event in {}..{} where {}.'.format(
                fmt_time(t0, ts), fmt_time(t1, ts), cond_text))
        return

    # Interval/segment mode. A segment is an interval further split whenever
    # the displayed show-value tuple changes while the condition remains true.
    has_show = bool(show_sids)
    # Single-pass: build state up to t0, then process intervals t0+..t1
    state = {}
    results = _ResultRows() if limit == 0 else []
    total = 0
    truncated = False

    def emit_interval(a, b):
        return {'begin_ticks': a, 'begin_h': fmt_time(a, ts),
                'end_ticks': b, 'end_h': fmt_time(b, ts)}

    def append_result(row):
        nonlocal total, truncated
        total += 1
        if limit != 0 and len(results) >= limit:
            truncated = True
            return True
        results.append(row)
        return False

    active = False
    seg_start = None
    seg_values = None
    seg_meta = None
    init_checks_done = False

    # Interval mode is a STATE-per-timestamp query (unlike --changed's per-event
    # evaluation): _event_groups yields every value_change at one timestamp as a
    # group, which is applied together before the condition is evaluated once on
    # the resulting settled state. Reusing it removes the hand-rolled cur_t/group
    # regrouping and its duplicate 'final pending group' tail.
    for gt, ggroup in _event_groups(vcd, 0, t1, selected):
        if gt <= t0:
            for gsid, gval in ggroup:
                state[gsid] = gval
            continue

        if not init_checks_done:
            active = _any_clause_holds(state, clauses)
            seg_start = t0 if active else None
            if active and has_show:
                seg_values, seg_meta = _show_values(vcd, state, show_sids, verbose)
            init_checks_done = True

        # Apply this timestamp's group, then evaluate the condition on the
        # settled state.
        for gsid, gval in ggroup:
            state[gsid] = gval
        cond_ok = _any_clause_holds(state, clauses)
        if not has_show:
            if cond_ok and not active:
                active = True
                seg_start = gt
            elif not cond_ok and active:
                if append_result(emit_interval(seg_start, gt)):
                    break
                active = False
                seg_start = None
        else:
            if not cond_ok:
                if active:
                    row = emit_interval(seg_start, gt)
                    row['values'] = seg_values
                    if verbose:
                        row['meta'] = seg_meta
                    if append_result(row):
                        break
                    active = False
                    seg_start = None
                    seg_values = None
                    seg_meta = None
            else:
                new_values, new_meta = _show_values(vcd, state, show_sids, verbose)
                if not active:
                    active = True
                    seg_start = gt
                    seg_values = new_values
                    seg_meta = new_meta
                elif new_values != seg_values:
                    row = emit_interval(seg_start, gt)
                    row['values'] = seg_values
                    if verbose:
                        row['meta'] = seg_meta
                    if append_result(row):
                        break
                    seg_start = gt
                    seg_values = new_values
                    seg_meta = new_meta

    # If the selected signals produced no events in (t0, t1], the per-group init
    # check above never ran, so a condition that already holds across an
    # otherwise silent window would be missed (false "No interval"). Evaluate it
    # now from the baseline state; with no groups the final-interval emit below
    # reports the whole window.
    if not init_checks_done:
        active = _any_clause_holds(state, clauses)
        seg_start = t0 if active else None
        if active and has_show:
            seg_values, seg_meta = _show_values(vcd, state, show_sids, verbose)
        init_checks_done = True

    # Emit final interval if still active
    if active and not truncated:
        row = emit_interval(seg_start, t1)
        if has_show:
            row['values'] = seg_values
            if verbose:
                row['meta'] = seg_meta
        append_result(row)

    if args.json:
        key = 'segments' if has_show else 'intervals'
        obj = {'mode': 'segment' if has_show else 'interval',
               'condition': cond_label,
               'condition_resolved': cond_text,
               'show': [vcd.signals[sid]['path'] for sid in show_sids],
               'begin_ticks': t0, 'begin_h': fmt_time(t0, ts),
               'end_ticks': t1, 'end_h': fmt_time(t1, ts),
               'shown': len(results), 'truncated': truncated,
               **_trunc_hint(truncated, len(results), total, False, key),
               key: results}
        obj.update(_total_json_fields(total, truncated))
        _json(obj)
        return

    noun = 'segment' if has_show else 'interval'
    if results:
        print('Found: {} {}(s)'.format(_count_label(len(results), total, truncated), noun))
        for r in results:
            if has_show:
                print('  {:<12}..{:<12} {}'.format(
                    r['begin_h'], r['end_h'], _values_text(r['values'])))
            else:
                print('  {:<12}..{:<12} {}'.format(r['begin_h'], r['end_h'], cond_text))
        if truncated:
            print(_trunc_line_lower_bound(len(results), total, noun + 's'))
    else:
        print('No {} in {}..{} where {}.'.format(
            noun, fmt_time(t0, ts), fmt_time(t1, ts), cond_text))

