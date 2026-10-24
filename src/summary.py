# ================================================================
# Part 6: Window summary
# ================================================================

def _summary_rows(vcd, t0, t1, sids):
    """Return (rows, undefined, counts) for window summary.

    Baseline captures state up to init_boundary: t=0 when the window starts
    at 0 (so $dumpvars initialization is part of the baseline, not counted
    as changes), or t0-1 when the window starts later (so value_changes
    exactly at --begin are counted as in-window events, fixing the boundary
    black-hole where transitions at the window edge were silently dropped).

    Static means known (in the baseline, or first defined inside the window)
    with no value changes inside the window. Undefined means selected but never
    observed up to the window end. No unknown values are invented.

    Counting matches `search changed()`: a signal's first observation is not
    a change. A signal first defined inside the window takes that value as its
    `init` and reports `defined_at`; only later transitions count. Event
    variables count every trigger in [t0, t1] (they are markers, not levels),
    including triggers at t=0.

    For 1-bit signals, rise/fall counts are reported for clean 0->1 and 1->0
    transitions only. x/z-related transitions still count as changes, but not
    as rises/falls.

    The distinct-value count (`unique`) is exact up to
    VCD_ANALYZER_MAX_UNIQUE_VALUES (default 65536, read per call like
    VCD_ANALYZER_TOKEN_CHUNK_SIZE); beyond the cap it is a lower bound, and
    the row says so: JSON `unique_is_exact: false` (the key appears only when
    capped), text `uniq=N+`. This bounds memory on e.g. a 32-bit counter over
    tens of millions of changes instead of keeping every value string alive.
    """
    selected = _selected_sids(vcd, sids)
    init_boundary = 0 if t0 == 0 else t0 - 1
    # Per-call env read so tests can shrink the cap via monkeypatch.setenv
    # without reloading the module.
    unique_cap = _env_int('VCD_ANALYZER_MAX_UNIQUE_VALUES', 65536)

    # Baseline: {sid: val} — cheap str overwrites, same as state_at.
    # Stats dicts are created only once per signal, not on every baseline event.
    baseline = {}
    stats = {}

    def _make_stats(info, init_val):
        # rise/fall apply to 1-bit levels; an event variable has no level.
        is_scalar = info['width'] == 1 and info.get('type') != 'event'
        return {
            'changes': 0, 'first_at': None, 'last_at': None,
            'initial': init_val, 'last': init_val,
            'unique': {init_val} if init_val is not None else set(),
            'unique_capped': False,
            'rise_count': 0 if is_scalar else None,
            'fall_count': 0 if is_scalar else None,
            'scalar': is_scalar,
        }

    for t, sid, prev, val, kind in vcd.iter_transitions(0, t1, selected):
        is_event = kind == 'event'
        if t <= init_boundary and not (is_event and t >= t0):
            baseline[sid] = val
            continue

        # First event in analysis window for this signal —
        # initialize stats from baseline snapshot (if any).
        if sid not in stats:
            init_val = baseline.pop(sid, None)
            if init_val is None and prev is None and not is_event:
                # First observation inside the window: it defines the signal,
                # it is not a transition (same rule as search changed()).
                stats[sid] = _make_stats(vcd.signals[sid], val)
                stats[sid]['defined_at'] = t
                continue
            stats[sid] = _make_stats(vcd.signals[sid], init_val)

        s = stats[sid]
        # Count genuine transitions only. prev (carried by the transition
        # stream) is the value observed just before this change; on the first
        # in-window event it equals the baseline value, so a $dumpall/$dumpon
        # checkpoint re-emitting the current value (prev == val) is not counted
        # and a never-changing signal stays static. Repeated event-variable
        # triggers at the same value are likewise not double-counted here — dump
        # and search --changed expose each trigger; summary counts genuine value
        # transitions.
        if val != prev or is_event:
            if s['scalar'] and not is_event:
                if prev == '0' and val == '1':
                    s['rise_count'] += 1
                elif prev == '1' and val == '0':
                    s['fall_count'] += 1
            s['changes'] += 1
            if s['first_at'] is None:
                s['first_at'] = t
            s['last_at'] = t
            s['last'] = val
            # Once capped the set is frozen, so skip the per-value hash
            # entirely — this is the exact tens-of-millions hot path the cap
            # exists for.
            if not s['unique_capped'] and val not in s['unique']:
                if len(s['unique']) < unique_cap:
                    s['unique'].add(val)
                else:
                    # At cap: the count stays a lower bound, flagged on the row.
                    s['unique_capped'] = True

    # Signals that were in baseline but had no in-window events (static).
    for sid, val in baseline.items():
        stats[sid] = _make_stats(vcd.signals[sid], val)

    rows = []
    for sid in sorted(stats, key=lambda x: vcd.signals[x]['path']):
        info = vcd.signals[sid]
        s = stats[sid]
        kind = 'active' if s['changes'] else 'static'
        row = {
            'kind': kind,
            'path': info['path'],
            'value': fmt_val(s['last'], info) if kind == 'static' else None,
            'changes': s['changes'],
            'rise_count': s['rise_count'],
            'fall_count': s['fall_count'],
            'init': _fmt_maybe(s['initial'], info),
            'last': _fmt_maybe(s['last'], info),
        }
        if s.get('defined_at') is not None:
            row['defined_at_ticks'] = s['defined_at']
            row['defined_at_h'] = fmt_time(s['defined_at'], vcd.ts_sec)
        if s['first_at'] is not None:
            row['first_at_ticks'] = s['first_at']
            row['first_at'] = fmt_time(s['first_at'], vcd.ts_sec)
            row['first_at_h'] = row['first_at']
            row['last_at_ticks'] = s['last_at']
            row['last_at'] = fmt_time(s['last_at'], vcd.ts_sec)
            row['last_at_h'] = row['last_at']
        if s['unique']:
            row['unique'] = len(s['unique'])
            if s['unique_capped']:
                row['unique_is_exact'] = False
        row['_width'] = info['width']
        row['_type'] = info.get('type', 'wire')
        rows.append(row)

    undefined = sorted(selected - set(stats), key=lambda x: vcd.signals[x]['path'])
    counts = {
        'selected': len(selected), 'defined': len(stats), 'undefined': len(undefined),
        'active': sum(1 for r in rows if r['kind'] == 'active'),
        'static': sum(1 for r in rows if r['kind'] == 'static'),
    }
    return rows, undefined, counts

def _public_row(row, verbose=False):
    r = dict(row)
    width = r.pop('_width', None)
    typ = r.pop('_type', None)
    if verbose:
        r['width'] = width
        r['type'] = typ
    return r


