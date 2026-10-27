# ================================================================
# Part 4: Block index (optional sidecar accelerator)
# ================================================================

# An optional <file>.vcidx sidecar gives point queries and narrow windows
# random access instead of a full-file scan: blocks of the data section are
# indexed per raw symbol (posting = block id + last-record offset). No
# waveform values are persisted. Building is explicit (`vcd_analyzer index
# <file>`); use is automatic when a fresh sidecar exists and the per-file
# gate (index_advisable) says the index wins. The fast distribution variant
# embeds a native builder library (C ABI via ctypes) and replaces the pure
# Python build pass below; queries are identical either way. Disable with
# VCD_ANALYZER_NO_INDEX=1 (never use).

HEADER = struct.Struct('<8sQQQQQQ')
BLOCK = struct.Struct('<QQqq')
DIRECTORY = struct.Struct('<QII')
POSTING = struct.Struct('<II')
MAGIC = b'VCDIDX01'
MAGIC2 = b'VCDIDX02'   # same layout; postings may use the compact modes below
# Posting entry encodings by directory mode. fmt reads ONE entry; size is the
# stride; runs marks block-RANGE pairs (no record pointers) vs point pairs.
# Modes 0/1 are the original 8-byte encodings (VCDIDX01, Python builder);
# 2/3 are the compact 6/4-byte forms written by the Rust builder when the
# block count fits u16.
ENTRY = {
    0: (struct.Struct('<II'), 8, False),
    1: (struct.Struct('<II'), 8, True),
    2: (struct.Struct('<HI'), 6, False),
    3: (struct.Struct('<HH'), 4, True),
}
# Content-fingerprint footer, appended after the postings by both builders.
# The header's (size, mtime_ns) catches every ordinary rewrite in O(1); the
# footer also catches a DIFFERENT dump that arrives with the same size and a
# preserved mtime (cp -p, rsync -t, tar/zip extraction). It hashes a fixed
# number of small samples spread evenly over the source — the header region
# ($date/$version) and the tail included — so verifying it costs the same few
# positioned reads whatever the file size. A sidecar without the footer
# (written by 1.6.0) counts as stale and is rebuilt.
FOOTER = struct.Struct('<8sII16s')
FOOTER_MAGIC = b'VCDFPR01'
FINGERPRINT_SAMPLES = 8
FINGERPRINT_SAMPLE_BYTES = 4096


class _CorruptSidecarError(RuntimeError):
    """The sidecar failed an on-demand integrity check (e.g. a posting
    names a block beyond the table). Callers fall back to the plain
    parser for the affected query instead of surfacing the error."""


def _pread(fd, size, offset):
    """os.pread for both worlds. POSIX has the atomic positional read;
    Windows gets seek+read, which is equivalent here: every fd in this
    module is consumed by exactly one single-threaded reader."""
    if hasattr(os, 'pread'):
        return os.pread(fd, size, offset)
    os.lseek(fd, offset, os.SEEK_SET)
    return os.read(fd, size)


def _source_fingerprint(fd, size, samples=FINGERPRINT_SAMPLES,
                        sample_bytes=FINGERPRINT_SAMPLE_BYTES):
    digest = hashlib.blake2b(struct.pack('<QII', size, samples, sample_bytes),
                             digest_size=16)
    if size <= samples * sample_bytes:
        offsets = range(0, size, sample_bytes)  # small file: all of it
    else:
        span = size - sample_bytes
        offsets = [span * k // (samples - 1) for k in range(samples)]
    for offset in offsets:
        digest.update(_pread(fd, sample_bytes, offset))
    return digest.digest()


def _footer_mismatch(footer, fd, size):
    """Why the footer bytes do not vouch for the source behind fd, or None."""
    if len(footer) != FOOTER.size:
        return 'truncated index'
    magic, samples, sample_bytes, digest = FOOTER.unpack(footer)
    if magic != FOOTER_MAGIC:
        return 'no content fingerprint (built by an older version); rebuild it'
    if not (2 <= samples <= 64 and 1 <= sample_bytes <= 1 << 20):
        return 'corrupt content fingerprint'
    if _source_fingerprint(fd, size, samples, sample_bytes) != digest:
        return 'stale index (source content changed)'
    return None


def _seal_sidecar(path, built, sidecar):
    """Append the fingerprint footer to a freshly built sidecar and publish
    it atomically at `sidecar` (the builders write to `built`). The source
    must still match the size/mtime the builder recorded, so the footer can
    only ever describe the bytes the index was built from."""
    published = False
    try:
        with open(built, 'rb') as f:
            head = f.read(24)
        _magic, size, mtime = struct.unpack_from('<8sQQ', head, 0)
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
        try:
            stat = os.fstat(fd)
            if (stat.st_size, stat.st_mtime_ns) != (size, mtime):
                raise ValueError('source changed while building index')
            footer = FOOTER.pack(FOOTER_MAGIC, FINGERPRINT_SAMPLES,
                                 FINGERPRINT_SAMPLE_BYTES,
                                 _source_fingerprint(fd, size))
        finally:
            os.close(fd)
        with open(built, 'ab') as f:
            f.write(footer)
        os.replace(built, sidecar)
        published = True
    finally:
        if not published:
            try:
                os.unlink(built)
            except OSError:
                pass


class PositionedToken(str):
    def __new__(cls, value, offset):
        obj = str.__new__(cls, value)
        obj.offset = offset
        return obj


def tokens(fd, start, end, counters=None, chunk_size=1 << 20):
    """Binary offsets, ASCII VCD whitespace, UTF-8 replacement for token text."""
    position = start
    carry = b''
    base = start
    while position < end:
        chunk = _pread(fd, min(chunk_size, end-position), position)
        if not chunk:
            break
        if counters is not None:
            counters['bytes'] += len(chunk)
            counters['reads'] += 1
        position += len(chunk)
        data = carry + chunk
        cut = len(data)
        if data and data[-1] not in b' \t\r\n\v\f' and position < end:
            cut = max(data.rfind(bytes((c,))) for c in b' \t\r\n\v\f') + 1
        for match in re.finditer(rb'\S+', data[:cut]):
            token = match.group().decode('utf-8', 'replace')
            if len(token.split()) != 1:
                raise ValueError('non-ASCII whitespace inside a token is not supported '
                                 'by the index builder')
            if len(token) > MAX_DATA_TOKEN_LEN:
                raise _VCDResourceError('VCD token too long')
            yield PositionedToken(token, base + match.start())
        carry = data[cut:]
        if len(carry) > MAX_DATA_TOKEN_LEN * 4:
            raise _VCDResourceError('VCD token too long')
        base += cut
    if carry:
        yield PositionedToken(carry.decode('utf-8', 'replace'), base)


def data_start(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
    try:
        iterator = tokens(fd, 0, os.fstat(fd).st_size)
        keyword = None
        for token in iterator:
            if keyword is None:
                if token in _DECL_KEYWORDS:
                    keyword = token
            elif token == '$end':
                if keyword == '$enddefinitions':
                    return token.offset + 4
                keyword = None
        return os.fstat(fd).st_size
    finally:
        os.close(fd)


def items(parser, fd, start, end, initial_time=0, counters=None, chunk_size=1 << 20):
    """Yield top-level grammar units, using the existing value decoder.

    (offset, time-before-unit, kind, time-after-unit, symbol, raw-value).
    Cuts between units preserve multi-token b/r/p and skipped section context.
    """
    iterator = tokens(fd, start, end, counters, chunk_size)
    pushback = []
    current = initial_time
    def nxt():
        return pushback.pop() if pushback else next(iterator, None)
    while True:
        token = nxt()
        if token is None:
            return
        before = current
        c0 = token[0]
        if c0 == '$':
            yield token.offset, before, 'marker', current, None, None
            if token == '$end' or token in _SIM_KEYWORDS:
                continue
            while True:
                other = nxt()
                if other is None or other == '$end':
                    break
            continue
        if c0 == '#' and len(token) > 1 and token[1].isdigit():
            # NOTE: Python's int() accepts non-ASCII digits ('#٥' -> 5).
            # The native builder refuses such tokens entirely and defers
            # to THIS builder, which shares the parser's exact semantics —
            # so indexed behavior never diverges from the plain parser.
            value = _parse_vcd_timestamp_token(token)
            if value is None:
                # Tolerated malformed timestamp (e.g. '#1.5'): the reference
                # parser skips it entirely, so it must not act as a commit
                # point for pending bus writes either.
                yield token.offset, before, 'marker', current, None, None
                continue
            if value < current:
                raise ValueError('non-monotonic timestamps: index requires fallback')
            current = value
            yield token.offset, before, 'time', current, None, None
            continue
        if c0 in '01xXzZ' and len(token) > 1:
            parsed = token[1:], c0.lower()
        elif c0 in 'bBrRp':
            parsed = parser._consume_value_change(token, nxt, pushback)
        else:
            parsed = None
        if parsed is not None:
            yield token.offset, before, 'value', current, parsed[0], parsed[1]
        else:
            yield token.offset, before, 'marker', current, None, None


def raw_symbols(parser):
    out = [sid for sid, info in parser.signals.items() if not info.get('synthesized')]
    seen = set(out)
    out.extend(s for s in parser._bit_map if s not in seen)
    return out


def build_index(path, sidecar, block_bytes=8 << 20, budget_bytes=None):
    start_clock = time.perf_counter()
    parser = VCDParser(str(path))
    header_seconds = time.perf_counter() - start_clock
    symbols = raw_symbols(parser)
    raw_id = {s: i for i, s in enumerate(symbols)}
    memberships = [array('I') for _ in symbols]
    last_positions = [array('I') for _ in symbols]
    modes = bytearray(len(symbols))  # 0: block/last-offset pairs; 1: membership runs
    payload_bytes = 0
    conversions = 0
    coarsens = 0
    initial_block_bytes = block_bytes
    if budget_bytes is not None and HEADER.size + DIRECTORY.size*len(symbols) > budget_bytes:
        raise ValueError('budget smaller than fixed signal directory; time-only fallback required')
    blocks = []
    recent = {}
    current = 0
    start = data_start(path)
    block_start = start
    block_initial = 0
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
    stat_before = os.fstat(fd)
    def as_runs(bids):
        runs = array('I')
        for bid in bids:
            if runs and runs[-1] == bid:
                runs[-1] = bid+1
            else:
                runs.extend((bid,bid+1))
        return runs
    def enforce_budget():
        nonlocal payload_bytes, conversions, coarsens, block_bytes, blocks
        if budget_bytes is None:
            return
        fixed = HEADER.size + DIRECTORY.size*len(symbols)
        target = int(budget_bytes*0.75)
        # Structural choice, independent of which signals have been queried:
        # very dense postings lose fine pointers in exchange for short ranges.
        for sid,bids in enumerate(memberships):
            if modes[sid] or len(bids)<8:continue
            runs=0;previous=-2
            for bid in bids:
                if bid!=previous+1:runs+=1
                previous=bid
            if runs*8<=len(bids):
                memberships[sid]=as_runs(bids)
                last_positions[sid]=array('I')
                modes[sid]=1;payload_bytes-=(len(bids)-runs)*8;conversions+=1
        if fixed + len(blocks)*BLOCK.size + payload_bytes <= target:
            return
        candidates = []
        for sid,bids in enumerate(memberships):
            if modes[sid] or len(bids)<4:
                continue
            runs = 0; previous = -2
            for bid in bids:
                if bid != previous+1:runs += 1
                previous=bid
            saving=(len(bids)-runs)*POSTING.size
            if saving>0:candidates.append((saving,sid))
        for saving,sid in sorted(candidates,reverse=True):
            memberships[sid]=as_runs(memberships[sid])
            last_positions[sid]=array('I')
            modes[sid]=1; payload_bytes-=saving; conversions+=1
            if fixed+len(blocks)*BLOCK.size+payload_bytes<=target:
                return
        while fixed+len(blocks)*BLOCK.size+payload_bytes>target:
            if len(blocks)<=1:
                if fixed+len(blocks)*BLOCK.size+payload_bytes<=budget_bytes:return
                raise ValueError('budget cannot hold even a single-block directory')
            old=blocks
            blocks=[(old[i][0],old[min(i+1,len(old)-1)][1],
                     old[i][2],old[min(i+1,len(old)-1)][3]) for i in range(0,len(old),2)]
            for sid in range(len(symbols)):
                if modes[sid]:
                    updated=array('I')
                    for i in range(0,len(memberships[sid]),2):
                        a=memberships[sid][i]//2;b=(memberships[sid][i+1]+1)//2
                        if updated and a<=updated[-1]:updated[-1]=max(updated[-1],b)
                        else:updated.extend((a,b))
                    memberships[sid]=updated
                else:
                    bids=array('I');positions=array('I')
                    for bid,relative in zip(memberships[sid],last_positions[sid]):
                        newbid=bid//2
                        newrelative=old[bid][0]+relative-blocks[newbid][0]
                        if bids and bids[-1]==newbid:positions[-1]=newrelative
                        else:bids.append(newbid);positions.append(newrelative)
                    memberships[sid]=bids;last_positions[sid]=positions
            payload_bytes=sum(len(values)*(4 if modes[sid] else 8)
                              for sid,values in enumerate(memberships))
            block_bytes*=2;coarsens+=1
    def flush(end):
        nonlocal recent, block_start, block_initial, payload_bytes
        if end <= block_start:
            return
        block_id = len(blocks)
        blocks.append((block_start, end, block_initial, current))
        for sid, position in recent.items():
            if modes[sid]:
                if memberships[sid] and memberships[sid][-1]==block_id:
                    memberships[sid][-1]=block_id+1
                else:
                    memberships[sid].extend((block_id,block_id+1));payload_bytes+=8
            else:
                memberships[sid].append(block_id)
                last_positions[sid].append(position - block_start);payload_bytes+=8
        recent = {}
        block_start = end
        block_initial = current
        enforce_budget()
    try:
        for position, before, kind, after, symbol, _value in items(
                parser, fd, start, stat_before.st_size):
            if position - block_start >= block_bytes:
                flush(position)
            current = after
            if kind == 'value' and symbol in raw_id:
                recent[raw_id[symbol]] = position
        flush(stat_before.st_size)
        stat_after = os.fstat(fd)
        if (stat_before.st_size, stat_before.st_mtime_ns) != (
                stat_after.st_size, stat_after.st_mtime_ns):
            raise ValueError('source changed while building index')
    finally:
        os.close(fd)
    pairs = sum(sum(values[i+1]-values[i] for i in range(0,len(values),2))
                if modes[sid] else len(values) for sid,values in enumerate(memberships))
    posting_start = HEADER.size + BLOCK.size * len(blocks) + DIRECTORY.size * len(symbols)
    # Atomic publication: concurrent readers must never see a half-written
    # sidecar whose fresh-claiming header already matches.
    sidecar_tmp = str(sidecar) + '.tmp.{}'.format(os.getpid())
    out = open(sidecar_tmp, 'wb')
    _published = False
    try:
        out.write(HEADER.pack(MAGIC, stat_after.st_size, stat_after.st_mtime_ns,
                              block_bytes, len(blocks), len(symbols), start))
        for block in blocks:
            out.write(BLOCK.pack(*block))
        location = posting_start
        for sid,posting in enumerate(memberships):
            count=len(posting)//2 if modes[sid] else len(posting)
            out.write(DIRECTORY.pack(location,count,modes[sid]))
            location += count * POSTING.size
        for sid,(bids, offsets) in enumerate(zip(memberships, last_positions)):
            buf = bytearray()
            entries=zip(bids[::2],bids[1::2]) if modes[sid] else zip(bids,offsets)
            for bid, off in entries:
                buf.extend(POSTING.pack(bid, off))
                if len(buf) >= 1 << 20:
                    out.write(buf); buf.clear()
            out.write(buf)
        out.close()
        _seal_sidecar(path, sidecar_tmp, sidecar)
        _published = True
    finally:
        if not _published:
            # Builder-owned cleanup: a failed build —
            # write error, publish error, anything — removes its OWN temp
            # file; the published sidecar (if any) was never touched by
            # this pass.
            try:
                out.close()
            except OSError:
                pass
            try:
                os.unlink(sidecar_tmp)
            except OSError:
                pass
    # Compare encodings WITHOUT pretending they are actual measured sidecars.
    membership_delta_bytes = 0
    membership_bitset_bytes = 0
    for sid,bids in enumerate(memberships):
        if modes[sid]:
            membership_delta_bytes+=sum(bids[i+1]-bids[i] for i in range(0,len(bids),2))
            membership_bitset_bytes+=(len(blocks)+7)//8 if bids else 0
            continue
        previous = -1
        for bid in bids:
            delta = bid - previous
            membership_delta_bytes += max(1, (delta.bit_length() + 6)//7)
            previous = bid
        membership_bitset_bytes += (len(blocks)+7)//8 if bids else 0
    return {
        'build_s': time.perf_counter()-start_clock,
        'header_s': header_seconds, 'source_bytes': stat_after.st_size,
        'index_bytes': os.path.getsize(sidecar), 'blocks': len(blocks),
        'raw_symbols': len(symbols), 'signal_block_pairs': pairs,
        'membership_delta_payload_bytes': membership_delta_bytes,
        'membership_bitset_payload_bytes': membership_bitset_bytes,
        'directory_bytes': HEADER.size + BLOCK.size*len(blocks) + DIRECTORY.size*len(symbols),
        'max_block_bytes': max((b[1]-b[0] for b in blocks), default=0),
        'raw_block_bytes': block_bytes,
        'initial_block_bytes': initial_block_bytes,
        'budget_bytes': budget_bytes,
        'run_encoded_signals': sum(modes),
        'coarsen_count': coarsens,
    }


class IndexedVCD(VCDParser):
    """All-signal random access without persistent values or snapshots."""
    def __init__(self, path, sidecar, enforce_gate=True):
        super().__init__(str(path))
        self._enforce_gate = enforce_gate
        # Freshness first, handles second: a stale sidecar must not leak the
        # source fd (a leaked fd makes lsof report OURSELVES as the writer,
        # permanently blocking auto-rebuild).
        _st = os.stat(path)
        with open(sidecar, 'rb') as _probe:
            _head = _probe.read(24)
        if len(_head) < 24:
            raise ValueError('truncated index')
        _magic, _size, _mtime = struct.unpack_from('<8sQQ', _head, 0)
        if (_magic not in (MAGIC, MAGIC2) or _size != _st.st_size
                or _mtime != _st.st_mtime_ns):
            raise ValueError('stale index')
        self.fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
        try:
            self.index_file = open(sidecar, 'rb')
            self.mapping = mmap.mmap(self.index_file.fileno(), 0,
                                     access=mmap.ACCESS_READ)
            (magic, size, mtime, self.block_bytes, nb, ns,
             self.begin_offset) = HEADER.unpack_from(self.mapping)
            stat = os.fstat(self.fd)
            if (magic not in (MAGIC, MAGIC2) or size != stat.st_size
                    or mtime != stat.st_mtime_ns):
                raise ValueError('stale index')
            body_end = len(self.mapping) - FOOTER.size
            if body_end < HEADER.size:
                raise ValueError('truncated index')
            reason = _footer_mismatch(self.mapping[body_end:], self.fd, size)
            if reason:
                raise ValueError(reason)
            self.file_size = size
            self.symbols = raw_symbols(self)
            if ns != len(self.symbols):
                raise ValueError('signal directory mismatch')
            self.raw_id = {sid: k for k, sid in enumerate(self.symbols)}
            # Full structural validation NOW, not at first corrupt read:
            # a damaged directory (bad mode byte, postings past EOF,
            # non-monotonic block ends) must fall back to the plain parser
            # here, never surface as KeyError/struct.error mid-query.
            if nb * BLOCK.size + HEADER.size > body_end:
                raise ValueError('truncated block table')
            self.blocks = [BLOCK.unpack_from(
                self.mapping, HEADER.size + k * BLOCK.size) for k in range(nb)]
            self.ends = [b[3] for b in self.blocks]
            prev_end = -1
            for _s, _e, t0, t1 in self.blocks:
                if t1 < t0 or t0 < prev_end or _e < _s:
                    raise ValueError('corrupt block table')
                prev_end = t1
            self.directory_start = directory_start = HEADER.size + nb * BLOCK.size
            # selected-signal -> raw identifier mapping (bit buses included)
            self.sources = {sid: {sid} for sid, info in self.signals.items()
                            if not info.get('synthesized')}
            for sym, refs in self._bit_map.items():
                for gid, _bit in refs:
                    self.sources.setdefault(gid, set()).add(sym)
            blob_start = directory_start + ns * DIRECTORY.size
            if blob_start > body_end:
                raise ValueError('truncated directory')
            for k in range(ns):
                location, count, flags = DIRECTORY.unpack_from(
                    self.mapping, directory_start + k * DIRECTORY.size)
                if flags not in ENTRY:
                    raise ValueError('corrupt posting mode')
                _fmt, esize, _runs = ENTRY[flags]
                if location < blob_start or location + count * esize > body_end:
                    raise ValueError('posting range out of bounds')
        except Exception:
            self.close()
            raise
        self.reset_counters()
        self._advisable = None
    def close(self):
        for name, closer in (('mapping', lambda: self.mapping.close()),
                             ('index_file', lambda: self.index_file.close())):
            attr = self.__dict__.get(name)
            if attr is not None:
                closer()
        fd = self.__dict__.get('fd')
        if fd is not None:
            os.close(fd)
    def reset_counters(self):
        self.counters = {'bytes': 0, 'reads': 0, 'blocks': 0, 'point_records': 0,
                         'point_reads': 0}
    def index_advisable(self):
        """Per-file usage gate; False means 'a plain source scan wins'.

        Two load-time facts decide the regime, both O(1):
          data_bytes = file size - data-section start
          bytes of data per raw symbol = data_bytes / raw symbol count
        Header-heavy dumps (formal traces, post-processed collapses) declare
        thousands of $var symbols over a tiny data section: the fixed 12 B
        directory per symbol and one point read per selected symbol make the
        index SLOWER than the raw scan it replaces (wlf_2_full: 8ms -> 34ms).
        Gate: data >= 128 KiB AND data >= 64 x raw_symbols. Calibrated on the
        real corpus so every observed winning file passes and every losing
        file is rejected; files below the floor scan in single-digit ms raw.
        The decision is computed even when enforcement is disabled (tests,
        benchmarks) so callers can introspect what production would do.
        """
        if self._advisable is None:
            data=self.file_size-self.begin_offset
            self._advisable=(data>=128<<10 and data>=64*len(self.raw_id))
        return self._advisable
    def _gate_rejects(self):
        return self._enforce_gate and not self.index_advisable()
    def selected_raw(self, sids):
        result = set()
        for sid in self.signals if sids is None else sids:
            result.update(self.sources[sid])
        return result
    def posting(self, sym, block):
        location, count, flags = DIRECTORY.unpack_from(
            self.mapping, self.directory_start+self.raw_id[sym]*DIRECTORY.size)
        entry, size, runs = ENTRY[flags]
        lo = 0; hi = count
        while lo < hi:
            mid = (lo+hi)//2
            bid = entry.unpack_from(self.mapping, location+mid*size)[0]
            if bid <= block: lo = mid+1
            else: hi = mid
        if lo == 0: return None
        bid,second = entry.unpack_from(self.mapping, location+(lo-1)*size)
        if bid >= len(self.blocks):
            raise _CorruptSidecarError('posting names block {} of {}'.format(
                bid, len(self.blocks)))
        return (min(block,second-1),None) if runs else (bid,second)
    def candidate_blocks(self, required, t0, t1, include_range=False):
        blocks = set()
        ranges = set()
        first = bisect.bisect_left(self.ends, t0)
        last=len(self.blocks)-1 if t1 is None else bisect.bisect_right([b[2] for b in self.blocks],t1)-1
        for sym in required:
            location, count, flags = DIRECTORY.unpack_from(
                self.mapping, self.directory_start+self.raw_id[sym]*DIRECTORY.size)
            entry, size, runs = ENTRY[flags]
            if runs:
                lo=0;hi=count
                while lo<hi:
                    mid=(lo+hi)//2
                    end=entry.unpack_from(self.mapping,location+mid*size)[1]
                    if end<=first:lo=mid+1
                    else:hi=mid
                while lo<count:
                    a,b=entry.unpack_from(self.mapping,location+lo*size)
                    if a>=len(self.blocks) or b>len(self.blocks):
                        raise _CorruptSidecarError('posting range {}-{} of {} blocks'.format(a,b,len(self.blocks)))
                    if a>last:break
                    a=max(a,first);b=min(b,last+1)
                    if a<b:ranges.add((a,b))
                    lo+=1
                continue
            # Rightmost <= first-1, then visit postings from first onward.
            lo = 0; hi = count
            while lo < hi:
                mid=(lo+hi)//2
                bid=entry.unpack_from(self.mapping,location+mid*size)[0]
                if bid < first:lo=mid+1
                else:hi=mid
            while lo<count:
                bid=entry.unpack_from(self.mapping,location+lo*size)[0]
                if bid>=len(self.blocks):
                    raise _CorruptSidecarError('posting names block {} of {}'.format(bid,len(self.blocks)))
                if t1 is not None and self.blocks[bid][2]>t1:break
                blocks.add(bid);lo+=1
        for a,b in ranges:blocks.update(range(a,b))
        if include_range and blocks:
            # Bit-exploded buses commit at EVERY top-level '#T' — including
            # ones in blocks whose only content is a timestamp (no postings,
            # so they would otherwise be skipped). Until blocks carry a
            # has-timestamp bitmap, bus selections read the whole span.
            return list(range(min(blocks), max(blocks) + 1))
        return sorted(blocks)
    def block_items(self, bid):
        start,end,t0,_t1 = self.blocks[bid]
        self.counters['blocks'] += 1
        yield from items(self,self.fd,start,end,t0,self.counters)
    def point_value(self, sym, bid, relative):
        start,end,t0,_t1 = self.blocks[bid]
        self.counters['point_records'] += 1
        for _pos,_before,kind,_after,record_sym,val in items(
                self,self.fd,start+relative,end,t0,self.counters,chunk_size=4096):
            if kind=='value':
                assert record_sym==sym,(record_sym,sym)
                return val
        raise _CorruptSidecarError('indexed record missing')
    def point_values(self, bid, entries):
        """Resolve several same-block pointer postings by in-place record decode.

        The posting offset is the record's opening-token offset, recorded at
        build time AFTER the record passed _consume_value_change validation —
        so the record can be decoded directly instead of re-streamed. A first
        attempt merged the targets into one sequential scan, but that
        tokenizes every record BETWEEN scattered targets and measured SLOWER
        than the per-symbol scans it replaced (picorv32 hier 1.4ms -> 29.7ms).
        Here each target parses only its own 1-4 tokens over coalesced reads:
        work O(N records), IO O(clustered bytes) instead of one 4 KiB pread
        per symbol. A window truncated mid-record (wide vectors) falls back
        to the streaming point_value.
        """
        start,end,t0,_t1 = self.blocks[bid]
        targets=sorted((start+relative,sym) for sym,relative in entries)
        found={}
        self.counters['point_reads'] += 1
        self.counters['point_records'] += len(targets)
        i=0;n=len(targets)
        while i<n:
            # Targets within POINT_GROUP_SPAN share one pread.
            lo=targets[i][0];hi=lo;j=i
            while j<n and targets[j][0]-lo<=self.POINT_GROUP_SPAN:
                hi=targets[j][0];j+=1
            buf=_pread(self.fd,min(hi-lo+512,end-lo),lo)
            self.counters['reads'] += 1
            self.counters['bytes'] += len(buf)
            while i<j:
                off,sym=targets[i]
                val=self._record_in_buffer(buf,off-lo,sym)
                # None = window ends mid-record; stream-decode that one.
                found[sym]=(val if val is not None
                            else self.point_value(sym,bid,off-start))
                i+=1
        return found
    POINT_GROUP_SPAN = 1 << 16
    @staticmethod
    def _record_in_buffer(buf, rel, sym):
        """Decode the value_change whose opener token starts at buf[rel].

        Mirrors _consume_value_change's value mapping (scalar/b lowered,
        real verbatim, port states mapped) without re-validating what the
        build pass already validated; the identifier assertion is the
        corruption tripwire. None when the window is too short to complete
        the record; AssertionError when the offset does not sit on the
        expected record.
        """
        n=len(buf)
        def token(pos):
            while pos<n and buf[pos] in b' \t\r\n\v\f':pos+=1
            a=pos
            while pos<n and buf[pos] not in b' \t\r\n\v\f':pos+=1
            return (buf[a:pos].decode('utf-8','replace') if a<pos else None),pos
        tok,p=token(rel)
        if tok is None:return None
        c0=tok[0]
        def ident(pos):
            t,q=token(pos)
            if t is None:return None,None
            if t!=sym:raise _CorruptSidecarError('posting offset mismatch: {} != {}'.format(t,sym))
            return t,q
        if c0 in '01xXzZ':
            if tok[1:]!=sym:raise _CorruptSidecarError('posting offset mismatch: {} != {}'.format(tok[1:],sym))
            return c0.lower()
        if c0 in 'bB':
            t2,q=ident(p)
            if t2 is None:return None
            return tok[1:].lower()
        if c0 in 'rR':
            t2,q=ident(p)
            if t2 is None:return None
            return tok[1:]
        if c0=='p':
            # p<state> <strength0> <strength1> <id>: the two strengths are
            # single digits, not identifiers; only the 4th token is the sym.
            t2,q2=token(p)
            t3,q3=token(q2)
            if t3 is None:return None
            t4,q4=ident(q3)
            if t4 is None:return None
            return ''.join(_PORT_STATE[c] for c in tok[1:])
        raise _CorruptSidecarError('posting offset not at a value record: {} != {}'.format(tok,sym))
    def raw_at(self, t, required, pointers=True):
        if t<0 or not required:return {}
        complete=bisect.bisect_right(self.ends,t)-1
        partial=complete+1
        latest={}
        if partial<len(self.blocks) and self.blocks[partial][2]<=t:
            if any((p:=self.posting(sym,partial)) is not None and p[0]==partial for sym in required):
                for _pos,_before,kind,at,sym,val in self.block_items(partial):
                    if at>t:break
                    if kind=='value' and sym in required:latest[sym]=val
        grouped=defaultdict(list)
        for sym in required-latest.keys():
            posting=self.posting(sym,complete)
            if posting is not None:grouped[posting[0]].append((sym,posting[1]))
        for bid, entries in sorted(grouped.items()):
            if pointers and all(relative is not None for _sym,relative in entries):
                if len(entries)>1:
                    latest.update(self.point_values(bid,entries))
                else:
                    sym,relative=entries[0]
                    latest[sym]=self.point_value(sym,bid,relative)
            else:
                wanted={sym for sym,_ in entries}
                for _pos,_before,kind,_at,sym,val in self.block_items(bid):
                    if kind=='value' and sym in wanted:latest[sym]=val
        return latest
    def fold_raw(self, raw, sids):
        selected=self.signals.keys() if sids is None else sids
        state={}
        vec_width=self._vec_width
        for sid in selected:
            info=self.signals[sid]
            if not info.get('synthesized'):
                if sid in raw:
                    # 1.5.6 canonicalization: short 4-state vector values are
                    # left-extended to the declared width (b11 == b0011 on 4
                    # bits), over-wide logic values clamp to all-x. Real and
                    # event values are never padded (vec_width holds vectors).
                    val=raw[sid]
                    n=len(val);w=info['width']
                    if n<w and sid in vec_width and _is_4state_bits(val):
                        val=val.rjust(w,_PAD_CHAR[val[0]])
                    elif n>w:
                        val=_clamp_overwide_logic_value(val,info)
                    state[sid]=val
                continue
            bits=self._bit_state_template[sid][:]
            observed=False
            for sym in self.sources[sid]:
                if sym in raw:
                    value=raw[sym]
                    bit=value if len(value)==1 and _is_4state_bits(value) else 'x'
                    for gid,index in self._bit_map[sym]:
                        if gid==sid:bits[index]=bit;observed=True
            if observed:state[sid]=''.join(reversed(bits))
        return state
    def state_at(self,t_at,sids=None,pointers=True):
        if self._gate_rejects():
            # Gate rejected this file: header-heavy / data-tiny, where the
            # index costs more than the plain scan it replaces. Degrade to
            # the reference implementation; results stay identical.
            self.counters['gate_rejected']=True
            return super().state_at(t_at,sids)
        try:
            return self.fold_raw(self.raw_at(t_at,self.selected_raw(sids),pointers),sids)
        except _CorruptSidecarError:
            self.counters['corrupt_fallback']=True
            return super().state_at(t_at,sids)
    def state_pair(self,ta,tb,sids=None):
        return self.state_at(ta,sids),self.state_at(tb,sids)
    def _iter_changes(self,t0=0,t1=None,sids=None):
        if self._gate_rejects():
            self.counters['gate_rejected']=True
            yield from super()._iter_changes(t0,t1,sids)
            return
        required=self.selected_raw(sids)
        if not required:return
        try:
            # Bus commit fidelity needs the range read ONLY when this query
            # actually selects synthesized buses (a repeated '#T' with no bus
            # writes in between is a suppressed no-op; a gap '#T' terminating
            # a selected bus's writes is not). Scalar-only queries on a file
            # that merely CONTAINS buses must keep hit-block random access.
            needs_bus=(sids is None
                       or any(s in self._bit_state_template for s in sids))
            candidates=self.candidate_blocks(required,t0,t1,include_range=needs_bus)
        except _CorruptSidecarError:
            self.counters['corrupt_fallback']=True
            yield from super()._iter_changes(t0,t1,sids)
            return
        # When all of the file is relevant, its existing split-based scanner
        # is faster than the experimental position-aware decoder.
        if t0==0 and t1 is None and sum(self.blocks[b][1]-self.blocks[b][0] for b in candidates)>=0.8*(self.file_size-self.begin_offset):
            self.counters['fallback_to_source']=True
            self.counters['bytes_is_estimate']=True
            self.counters['bytes']+=self.file_size-self._data_offset
            yield from super()._iter_changes(t0,t1,sids)
            return
        raw=self.raw_at(t0-1,required)
        previous=self.fold_raw(raw,sids)
        selected=set(self.signals) if sids is None else sids
        vec_width=self._vec_width
        bit_state={gid:bits[:] for gid,bits in self._bit_state_template.items() if gid in selected}
        for sym,val in raw.items():
            bit=val if len(val)==1 and _is_4state_bits(val) else 'x'
            for gid,index in self._bit_map.get(sym,()):
                if gid in bit_state:bit_state[gid][index]=bit
        # Bit-exploded buses commit once per timestamp, matching the 1.5.6
        # parser: bit writes buffer until the tick ends, so cross-bit
        # intermediates never reach the stream; a second write to the SAME
        # bit in one tick is a genuine delta step and exposes the assembled
        # value it replaces first. Main commits at every '#T' token — a
        # repeated timestamp is two commit points — so each time marker
        # commits, and the tick boundary is otherwise detected from the
        # records themselves (a block may start mid-tick with no marker).
        bus_dirty={}
        def commit_buses():
            out=[(gid,''.join(reversed(bit_state[gid]))) for gid in bus_dirty]
            bus_dirty.clear()
            return out
        def emit(records,t):
            for sid,value in records:
                prev=previous.get(sid)
                if sid not in self._event_sids and prev==value:continue
                previous[sid]=value
                yield t,sid,prev,value
        cur_t=None
        stopped=False
        for bid in candidates:
            for _pos,_before,kind,t,sym,val in self.block_items(bid):
                if kind=='time':
                    yield from emit(commit_buses(),cur_t)
                    cur_t=t
                    if t1 is not None and t>t1:stopped=True;break
                    continue
                if kind!='value':continue
                if t!=cur_t:
                    yield from emit(commit_buses(),cur_t)
                    cur_t=t
                if t1 is not None and t>t1:stopped=True;break
                if t<t0 or sym not in required:continue
                bit=val if len(val)==1 and _is_4state_bits(val) else 'x'
                records=[]
                for gid,index in self._bit_map.get(sym,()):
                    if gid in bit_state:
                        written=bus_dirty.get(gid)
                        if written is None:
                            bus_dirty[gid]={index}
                        elif index in written:
                            if bit_state[gid][index]!=bit:
                                records.append((gid,''.join(reversed(bit_state[gid]))))
                            bus_dirty[gid]={index}
                        else:
                            written.add(index)
                        bit_state[gid][index]=bit
                if sym in selected and sym in self.signals:
                    info=self.signals[sym]
                    n=len(val);w=info['width']
                    # 1.5.6 canonicalization: pad short 4-state vectors to the
                    # declared width, clamp over-wide logic values to all-x.
                    if sym in vec_width and n<w and _is_4state_bits(val):
                        val=val.rjust(w,_PAD_CHAR[val[0]])
                    elif n>w:
                        val=_clamp_overwide_logic_value(val,info)
                    records.append((sym,val))
                yield from emit(records,t)
            if stopped:break
        if not stopped:
            yield from emit(commit_buses(),cur_t)



def sidecar_path(vcd_path):
    return str(vcd_path) + '.vcidx'


def native_index_build(path, sidecar, block_bytes):
    """Build via the embedded native library (full variant only).

    Fully automatic: the pure-Python builder is the fallback for every
    case the native path cannot serve — standard file without an embedded
    part, unsupported platform, or any load failure inside the loader.
    Returns None to signal that fallback.
    """
    build = globals().get('_NATIVE_INDEX_BUILD')
    if build is None:
        return None
    built = '{}.native.{}'.format(sidecar, os.getpid())
    try:
        stats = build(path, built, block_bytes)
        if stats is None:
            return None
        _seal_sidecar(path, built, sidecar)
    finally:
        try:
            os.unlink(built)  # left only when the build or the seal failed
        except OSError:
            pass
    stats['index_bytes'] = os.path.getsize(sidecar)
    return stats


def build_index_best(path, sidecar, block_bytes=8 << 20, threads=None):
    """Native build when the running file carries one, pure Python else."""
    if os.environ.get('VCD_ANALYZER_FAIL_INDEX'):
        raise ValueError('simulated index failure (VCD_ANALYZER_FAIL_INDEX)')
    if threads is not None:
        os.environ['VCD_ANALYZER_INDEX_THREADS'] = str(threads)
    try:
        stats = native_index_build(path, sidecar, block_bytes)
    except ValueError as error:
        # The native builder is ASCII-only and refuses some exotic tokens;
        # and build-fatal conditions (non-monotonic timestamps) re-raise
        # from the pure-Python pass below with the same user-facing error.
        _warn('native builder deferred to pure Python: {}'.format(error),
              cat='index_native_deferred')
        stats = None
    if stats is not None:
        stats['builder'] = 'native'
        return stats
    if os.environ.get('VCD_ANALYZER_INDEX_THREADS'):
        # Works identically on both variants; the thread count only feeds
        # the native builder, so say so instead of silently ignoring it.
        _warn('VCD_ANALYZER_INDEX_THREADS is ignored: no native builder '
              'is available on this platform', cat='index_threads_hint')
    stats = build_index(path, sidecar, block_bytes)
    stats['builder'] = 'python'
    return stats


def _variant_env_notice():
    """Full variant: every documented option works; nothing to warn about."""


def try_index(vcd_path):
    """IndexedVCD over a fresh, gate-passing sidecar, or None.

    A single upgrade point used by main(): None means 'run the plain
    parser'. A sidecar that exists but is stale or rejected by the gate
    falls back with one stderr warning so the stale file is discoverable.
    """
    if os.environ.get('VCD_ANALYZER_NO_INDEX'):
        return None
    sidecar = sidecar_path(vcd_path)
    if not os.path.exists(sidecar):
        return None
    try:
        idx = IndexedVCD(vcd_path, sidecar)
    except (ValueError, OSError, struct.error, KeyError) as error:
        # struct.error/KeyError: truncated or corrupt sidecar
        _warn('ignoring {} ({})'.format(sidecar, error), cat='index_stale')
        return None
    if not idx.index_advisable():
        idx.close()
        return None
    return idx


# -- index building: paths, auto-build, locking ------------------------------

_AUTO_SCRIPT_PATH = None  # set by main(): the running single-file script

# Smallest source a query builds an index for in the background. An indexed
# point query still parses up to one 8 MiB block (~0.1-1.8 s), while a plain
# scan grows with the queried time (~4 s at the end of 50 MB): around 30 MB
# the two break even, at 50 MiB the index is ~2x faster on average and ~40x
# at the end of the dump. Smaller files are left untouched; `index` still
# builds one on request at any size.
_AUTO_INDEX_MIN_BYTES = 50 << 20


def _sidecar_fresh(vcd_path, sidecar):
    """True when the sidecar header and fingerprint footer still match the
    source file (the same checks IndexedVCD applies before use)."""
    try:
        with open(sidecar, 'rb') as f:
            head = f.read(24)
            if len(head) < 24:
                return False
            f.seek(0, os.SEEK_END)
            if f.tell() < HEADER.size + FOOTER.size:
                return False
            f.seek(-FOOTER.size, os.SEEK_END)
            footer = f.read(FOOTER.size)
        magic, size, mtime = struct.unpack_from('<8sQQ', head, 0)
        fd = os.open(vcd_path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
        try:
            stat = os.fstat(fd)
            if not (magic in (MAGIC, MAGIC2) and size == stat.st_size
                    and mtime == stat.st_mtime_ns):
                return False
            return _footer_mismatch(footer, fd, size) is None
        finally:
            os.close(fd)
    except (OSError, struct.error):
        return False


def _writer_holds(vcd_path):
    """Why the VCD looks still-open-for-write, or None.

    Portable signal first: a dump modified seconds ago is almost certainly
    a live simulator output (they append continuously). Then lsof where
    available; on Windows, an open-for-write usually fails under another
    writer's share mode.
    """
    try:
        age = time.time() - os.stat(vcd_path).st_mtime
    except OSError:
        return None
    if age < 5.0:
        return 'modified {:.1f}s ago (still being written?)'.format(age)
    if sys.platform != 'win32':
        try:
            out = subprocess.run(['lsof', '-w', '--', vcd_path],
                                 capture_output=True, text=True, timeout=3)
            if out.returncode == 0 and out.stdout.strip():
                return 'open by another process (lsof)'
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        if not os.access(vcd_path, os.W_OK):
            return None  # read-only permission is not another writer
        try:
            fd = os.open(vcd_path, os.O_WRONLY)
            os.close(fd)
        except OSError:
            return 'locked by another process'
    return None


def _lock_fd(fd):
    """Exclusive non-blocking OS lock (flock on POSIX, msvcrt on Windows).
    Released automatically when the fd closes OR the process dies — the
    lock's lifetime is the build process's lifetime by construction."""
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _acquire_build_lock(sidecar):
    """Single-flight build lock held on an OPEN FILE DESCRIPTOR.

    Exclusion is the OS file lock, not the file's existence or contents:
    a dead builder releases automatically (no pid parsing, no stale
    heuristics — an empty or ancient lock file is harmless), and the
    pid is written for humans only. Returns the fd to hold for the
    build's duration, or None when another builder holds the lock.
    The lock file itself persists (a few bytes); unlinking it would
    re-introduce an unlink/lock race, so it is deliberately kept.
    """
    lock = sidecar + '.lock'
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | getattr(os, 'O_BINARY', 0),
                 0o600)
    try:
        _lock_fd(fd)
    except OSError:
        os.close(fd)  # held: another builder owns the build
        return None
    except BaseException:
        os.close(fd)
        raise
    try:
        os.ftruncate(fd, 0)
        os.write(fd, ('pid %d\n' % os.getpid()).encode())
    except OSError:
        pass  # informational only; exclusion never depends on it
    return fd


def _build_in_progress(sidecar):
    """True when a builder currently holds the lock (probe with an
    immediately-released fd; an unopenable lock counts as busy). The probe
    never creates the lock file: no lock file means no builder."""
    lock = sidecar + '.lock'
    try:
        fd = os.open(lock, os.O_RDWR | getattr(os, 'O_BINARY', 0))
    except FileNotFoundError:
        return False
    except OSError:
        return True
    try:
        _lock_fd(fd)
        return False
    except OSError:
        return True
    finally:
        os.close(fd)  # releases if the probe held it


def maybe_auto_build(parser, vcd_path):
    """Spawn ONE detached background index build when worthwhile.

    Triggered from a normal query when no sidecar exists, or an existing
    one is stale (source changed). A per-file OS-file-lock guarantees a
    single builder at a time; VCD_ANALYZER_AUTO_INDEX=0 disables; a source
    that looks still-open-for-write (fresh mtime / lsof holder / Windows
    lock) is reported and left alone. Never blocks or fails the query.

    Checks are ordered cheapest-first: a query already served by the index
    needs nothing, a file below _AUTO_INDEX_MIN_BYTES is never built
    automatically (one stat), a fresh sidecar needs nothing, a running
    builder or a live writer needs no native library — the
    base85+lzma+dlopen load happens only right before the spawn.

    The builder runs detached with no terminal; it writes <sidecar>.log
    only when the build fails (see cmd_index --auto).
    """
    if isinstance(parser, IndexedVCD):
        return  # the sidecar was fresh and is in use
    if os.environ.get('VCD_ANALYZER_AUTO_INDEX', '1').lower() in ('0', 'false', 'no'):
        return
    if _AUTO_SCRIPT_PATH is None:
        return  # imported as a library: no script to respawn
    vcd_path = os.path.abspath(vcd_path)
    try:
        if os.path.getsize(vcd_path) < _AUTO_INDEX_MIN_BYTES:
            return
    except OSError:
        return
    sidecar = sidecar_path(vcd_path)
    if os.path.exists(sidecar) and _sidecar_fresh(vcd_path, sidecar):
        return
    if _build_in_progress(sidecar):
        return  # a builder is already running for this file
    try:
        symbols = raw_symbols(parser)
        data = os.path.getsize(vcd_path) - data_start(vcd_path)
    except (OSError, _VCDResourceError):
        return
    if not (data >= 128 << 10 and data >= 64 * len(symbols)):
        return  # the gate would refuse it; do not build what we won't use
    held = _writer_holds(vcd_path)
    if held:
        _warn('{}: index not rebuilt automatically — source {} '
              '(rerun after the dump completes)'.format(vcd_path, held),
              cat='index_writer_holds:' + vcd_path)
        return
    # Without a native builder for this platform, an automatic build would
    # run the much slower pure-Python pass and hurt more than help — auto
    # building is OFF by default here; build explicitly with `index`
    # (which says so and reports the slower mechanism). Loaded LAST: only
    # a query that is about to spawn a builder pays for it.
    loader = globals().get('_load_native_library')
    if loader is None or loader() is None:
        _warn('automatic index building is disabled on this platform (no '
              'native builder); run the index command to build with the '
              'slower pure-Python mechanism', cat='index_auto_no_native')
        return
    try:
        subprocess.Popen(
            [sys.executable, _AUTO_SCRIPT_PATH, 'index', vcd_path, '--auto'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        _warn('{}: building index in the background '
              '(VCD_ANALYZER_AUTO_INDEX=0 disables)'.format(vcd_path),
              cat='index_autobuild:' + vcd_path)
    except OSError as error:
        _warn('{}: background index build failed to start: {}'.format(
            vcd_path, error), cat='index_autobuild')


# Pure-Python builds of sources at least this big carry a note that a
# native builder would have been much faster.
_SLOW_BUILD_NOTE_BYTES = 64 << 20


def _build_index_command(vcd, args):
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
         'threads': stats.get('threads', 1),
         'parallel_fallback': stats.get('parallel_fallback', False)}
    if args.json:
        if builder == 'python' and r['source_bytes'] >= _SLOW_BUILD_NOTE_BYTES:
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
    if builder == 'python' and r['source_bytes'] >= _SLOW_BUILD_NOTE_BYTES:
        # Full variant, no library for this platform: say so when the file
        # is big enough for the difference to matter.
        print('Note     : no native builder for this platform — building with '
              'the pure-Python index mechanism (much slower). Supported '
              'platforms build natively with up to 4 threads.')
    print('Use      : queries pick this up automatically; VCD_ANALYZER_NO_INDEX=1 disables')

def cmd_index(vcd, args):
    """The `index` command. A background build (--auto, spawned by
    maybe_auto_build with no terminal attached) keeps its diagnostics in
    memory and leaves <sidecar>.log behind only when the build fails; a
    successful build removes the log of an earlier failure."""
    if not getattr(args, 'auto', False):
        return _build_index_command(vcd, args)
    import io
    import traceback
    log_path = sidecar_path(args.file) + '.log'
    captured = io.StringIO()
    stderr = sys.stderr
    sys.stderr = captured
    failure = None
    try:
        _build_index_command(vcd, args)
    except SystemExit as stop:
        if stop.code not in (None, 0):
            failure = stop.code if isinstance(stop.code, str) \
                else 'exit status {}'.format(stop.code)
    except BaseException:
        failure = traceback.format_exc()
    finally:
        sys.stderr = stderr
    if failure is None:
        try:
            os.unlink(log_path)
        except OSError:
            pass
        return
    try:
        with open(log_path, 'w', encoding='utf-8') as log:
            log.write('{} background index build of {} failed\n{}{}\n'.format(
                time.strftime('%Y-%m-%d %H:%M:%S'), args.file,
                captured.getvalue(), str(failure).rstrip()))
    except OSError:
        pass
    sys.exit(1)


def _link_sidecar(sidecar, target):
    """Point <file>.vcidx at a custom --output location.

    Replaces a previous link; a pre-existing REGULAR file at the sidecar
    path is left untouched (never delete a file the user put there) and
    reported. A failed link is a warning, not an error: the sidecar at
    PATH is still valid, queries just will not find it automatically.
    """
    try:
        if os.path.islink(sidecar):
            os.unlink(sidecar)
        elif os.path.exists(sidecar):
            _warn('{}: occupied by a regular file; left in place '
                  '(index written to {})'.format(sidecar, target), cat='index_link')
            return
        os.symlink(target, sidecar)
    except OSError as error:
        _warn('index written to {} but queries look for {} '
              '(link failed: {})'.format(target, sidecar, error), cat='index_link')
