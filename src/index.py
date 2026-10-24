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
        chunk = os.pread(fd, min(chunk_size, end-position), position)
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
                raise ValueError('prototype does not support non-ASCII whitespace')
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
    fd = os.open(path, os.O_RDONLY)
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
            value = _parse_vcd_timestamp_token(token)
            if value is not None:
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
    fd = os.open(path, os.O_RDONLY)
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
    with open(sidecar, 'wb') as out:
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
        self.fd = os.open(path, os.O_RDONLY)
        self.index_file = open(sidecar, 'rb')
        self.mapping = mmap.mmap(self.index_file.fileno(), 0, access=mmap.ACCESS_READ)
        magic, size, mtime, self.block_bytes, nb, ns, self.begin_offset = HEADER.unpack_from(self.mapping)
        stat = os.fstat(self.fd)
        if magic not in (MAGIC, MAGIC2) or size != stat.st_size or mtime != stat.st_mtime_ns:
            raise ValueError('stale index')
        self.file_size = size
        self.symbols = raw_symbols(self)
        if ns != len(self.symbols):
            raise ValueError('signal directory mismatch')
        self.raw_id = {sid: i for i, sid in enumerate(self.symbols)}
        self.blocks = [BLOCK.unpack_from(self.mapping, HEADER.size+i*BLOCK.size) for i in range(nb)]
        self.ends = [b[3] for b in self.blocks]
        self.directory_start = HEADER.size + nb*BLOCK.size
        self.sources = {sid: {sid} for sid, info in self.signals.items() if not info.get('synthesized')}
        for sym, refs in self._bit_map.items():
            for gid, _bit in refs:
                self.sources.setdefault(gid, set()).add(sym)
        # Direct scope membership, not duplicated descendant sets.
        self.scope_direct = defaultdict(set)
        self.scope_children = defaultdict(set)
        for sid, info in self.signals.items():
            for scope in info.get('scopes', []):
                self.scope_direct[scope].add(sid)
                parts = scope.split('.')
                for depth in range(1, len(parts)+1):
                    parent = '.'.join(parts[:depth-1])
                    self.scope_children[parent].add('.'.join(parts[:depth]))
        self.reset_counters()
        self._advisable = None
    def close(self):
        self.mapping.close(); self.index_file.close(); os.close(self.fd)
    def reset_counters(self):
        self.counters = {'bytes': 0, 'reads': 0, 'blocks': 0, 'point_records': 0,
                         'point_reads': 0}
    def index_advisable(self):
        """Per-file usage gate; False means 'a plain source scan wins'.

        Two load-time facts decide the regime (PLAN.md §4.1), both O(1):
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
    def hier(self, scope):
        found = set(); pending = [scope]
        while pending:
            node = pending.pop()
            found.update(self.scope_direct.get(node, ()))
            pending.extend(self.scope_children.get(node, ()))
        return found
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
        return (min(block,second-1),None) if runs else (bid,second)
    def candidate_blocks(self, required, t0, t1):
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
                if t1 is not None and self.blocks[bid][2]>t1:break
                blocks.add(bid);lo+=1
        for a,b in ranges:blocks.update(range(a,b))
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
        raise AssertionError('indexed record missing')
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
            buf=os.pread(self.fd,min(hi-lo+512,end-lo),lo)
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
            if t!=sym:raise AssertionError('posting offset mismatch',{ 'at':t,'want':sym})
            return t,q
        if c0 in '01xXzZ':
            if tok[1:]!=sym:raise AssertionError('posting offset mismatch',{'at':tok[1:],'want':sym})
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
        raise AssertionError('posting offset not at a value record',{ 'tok':tok,'want':sym})
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
        return self.fold_raw(self.raw_at(t_at,self.selected_raw(sids),pointers),sids)
    def state_pair(self,ta,tb,sids=None):
        return self.state_at(ta,sids),self.state_at(tb,sids)
    def _iter_changes(self,t0=0,t1=None,sids=None):
        if self._gate_rejects():
            self.counters['gate_rejected']=True
            yield from super()._iter_changes(t0,t1,sids)
            return
        required=self.selected_raw(sids)
        if not required:return
        candidates=self.candidate_blocks(required,t0,t1)
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


def sidecar_path(vcd_path):
    return str(vcd_path) + '.vcidx'


def native_index_build(path, sidecar, block_bytes):
    """Build via the embedded native library (fast variant only).

    Fully automatic: the pure-Python builder is the fallback for every
    case the native path cannot serve — standard file without an embedded
    part, unsupported platform, or any load failure inside the loader.
    Returns None to signal that fallback.
    """
    build = globals().get('_NATIVE_INDEX_BUILD')
    if build is None:
        return None
    return build(path, sidecar, block_bytes)


def build_index_best(path, sidecar, block_bytes=8 << 20):
    """Native build when the running file carries one, pure Python else."""
    stats = native_index_build(path, sidecar, block_bytes)
    if stats is not None:
        stats['builder'] = 'native'
        return stats
    stats = build_index(path, sidecar, block_bytes)
    stats['builder'] = 'python'
    return stats


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
    except (ValueError, OSError) as error:
        _warn('ignoring {} ({})'.format(sidecar, error), cat='index_stale')
        return None
    if not idx.index_advisable():
        idx.close()
        return None
    return idx


# -- index building: paths, auto-build, locking ------------------------------

_AUTO_SCRIPT_PATH = None  # set by main(): the running single-file script


def _sidecar_fresh(vcd_path, sidecar):
    """True when the sidecar header still matches the source file."""
    try:
        with open(sidecar, 'rb') as f:
            head = f.read(24)
        if len(head) < 24:
            return False
        magic, size, mtime = struct.unpack_from('<8sQQ', head, 0)
        stat = os.stat(vcd_path)
        return (magic in (MAGIC, MAGIC2)
                and size == stat.st_size and mtime == stat.st_mtime_ns)
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
                                 capture_output=True, text=True, timeout=15)
            if out.returncode == 0 and out.stdout.strip():
                return 'open by another process (lsof)'
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            fd = os.open(vcd_path, os.O_WRONLY)
            os.close(fd)
        except OSError:
            return 'locked by another process'
    return None


def _lock_stale(lock, max_age=3600.0):
    """True when the build lock's owner is gone (dead pid / ancient)."""
    try:
        with open(lock) as f:
            pid = int(f.read().strip() or 0)
        if pid and pid != os.getpid():
            if sys.platform != 'win32':
                try:
                    os.kill(pid, 0)
                    return False  # alive and building
                except ProcessLookupError:
                    return True
                except PermissionError:
                    return False  # alive (owned by another user)
        age = time.time() - os.stat(lock).st_mtime
        return age > max_age
    except (OSError, ValueError):
        return True


def _acquire_build_lock(sidecar):
    lock = sidecar + '.lock'
    for _attempt in (0, 1):
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, 'w') as f:
                f.write(str(os.getpid()))
            return lock
        except FileExistsError:
            if _attempt == 0 and _lock_stale(lock):
                try:
                    os.unlink(lock)
                    continue
                except OSError:
                    pass
            return None
        except OSError:
            return None  # unwritable directory: cannot lock, cannot build
    return None


def maybe_auto_build(parser, vcd_path):
    """Spawn ONE detached background index build when worthwhile.

    Triggered from a normal query when no sidecar exists, or an existing
    one is stale (source changed). A per-file O_EXCL lock guarantees a
    single builder at a time; VCD_ANALYZER_AUTO_INDEX=0 disables; a source
    that looks still-open-for-write (fresh mtime / lsof holder / Windows
    lock) is reported and left alone. Never blocks or fails the query.
    """
    if os.environ.get('VCD_ANALYZER_AUTO_INDEX', '1').lower() in ('0', 'false', 'no'):
        return
    if _AUTO_SCRIPT_PATH is None:
        return  # imported as a library: no script to respawn
    vcd_path = os.path.abspath(vcd_path)
    sidecar = sidecar_path(vcd_path)
    if os.path.exists(sidecar) and _sidecar_fresh(vcd_path, sidecar):
        return
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
              cat='index_writer_holds')
        return
    lock = _acquire_build_lock(sidecar)
    if lock is None:
        return  # another builder owns it, or the directory is unwritable
    log = None
    try:
        try:
            log = open(sidecar + '.log', 'a')
        except OSError:
            log = None
        subprocess.Popen(
            [sys.executable, _AUTO_SCRIPT_PATH, 'index', vcd_path, '--auto'],
            stdout=log if log is not None else subprocess.DEVNULL,
            stderr=subprocess.STDOUT if log is not None else subprocess.DEVNULL,
            start_new_session=True, close_fds=True)
        _warn('{}: building index in the background '
              '(VCD_ANALYZER_AUTO_INDEX=0 disables)'.format(vcd_path),
              cat='index_autobuild')
    except OSError as error:
        _warn('{}: background index build failed to start: {}'.format(
            vcd_path, error), cat='index_autobuild')
        try:
            os.unlink(lock)
        except OSError:
            pass
    finally:
        if log is not None:
            log.close()


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
