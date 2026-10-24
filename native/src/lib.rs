// Fast block-index builder for vcd_analyzer — library form.
//
// Same grammar and sidecar format as the research prototype this was carved
// from (research/vcdidx.rs on the research/vcd-index branch): see the PARITY
// comment below. This crate adds the deployment surface:
//
//   * build_from_manifest() — callable core returning Result (a library must
//     never exit the host process, so every fatal path is an Err(String))
//   * vcdidx_abi_version / vcdidx_abi_build — a C ABI consumed through
//     ctypes by the single-file "fast" distribution variant
//   * the vcdidx binary (src/main.rs) wraps the same core for CLI use
//
// The Python side owns the VCD header (signal table, aliases, bit-exploded
// reassembly — the single source of truth) and pipes a manifest:
//
//   data_start <u64>
//   block_bytes <u64>
//   max_token_len <usize>
//   symbols <count>
//   <symbol id code>            (one per line, raw_symbols() order)
//
// Output: a VCDIDX02 sidecar — same header/block/directory layout as
// VCDIDX01, postings mode 2 = (u16 block, u32 offset) 6-byte entries when
// the block count fits u16 (mode 0 = the old 8-byte form otherwise), random
// access and binary search preserved.
//
// PARITY contract (differential-tested by verify/test_index*.py):
//   * tokens split on the 6 ASCII whitespace bytes, token length capped
//   * '$end' / $dump* markers are items; any other $section drains to $end
//     (drained body tokens are NOT items and never move a block boundary)
//   * '#'+digit tokens parse as timestamps; malformed '#1.5' is skipped;
//     Python int() accepts '1_0', so underscore forms parse too; >100
//     digits or >int64 is fatal; regressing timestamps are fatal
//   * scalar/b/r/p value changes; the operand of b/r/p is ALWAYS consumed
//     (mirroring Python, so a malformed value cannot leak its operand back
//     as a phantom item) except a '#<digits>' token NOT declared as a
//     symbol is structural and pushed back, dropping the record. p-record
//     strengths are fetched with a PLAIN token fetch (no structural rule)
//     and pushed back on failure in Python's order. Value VALIDATION is
//     computed before the operand fetch — a pure reorder with no observable
//     difference — so no token bytes need to outlive the fetch.
//   * block flush at the first ITEM whose position crosses block_bytes;
//     the crossing item opens the new block; block t1 is the time before
//     it, the next block's t0 the same value
//   * source (size, mtime_ns) must not change during the build
//   * any grammar-position token ('#', b, r, p openers) carrying a
//     non-ASCII byte is REFUSED (Err): Python's int()/regexes accept
//     Unicode digits, so instead of silently disagreeing with the
//     reference parser the caller defers to the pure-Python builder

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::os::raw::{c_char, c_int, c_uint};
use std::time::Instant;

const READ_CHUNK: usize = 16 << 20;

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

macro_rules! die {
    ($($arg:tt)*) => { return Err(format!($($arg)*)) };
}

// -- symbol table: direct index over printable-ASCII id codes --------------

const NONE: u32 = u32::MAX;

/// VCD identifier codes are printable ASCII (IEEE 1364 18.2.1), so codes of
/// 1..=3 bytes resolve through a flat 94+94²+94³ table (~3.4 MB) with no
/// hashing — this lookup is the per-record hot path on a 10 GiB dump.
/// Longer codes (only reachable past ~830k signals) use an FNV-hashed map.
struct SymTab {
    flat: Vec<u32>,
    rest: std::collections::HashMap<Vec<u8>, u32, std::hash::BuildHasherDefault<Fnv>>,
}

#[derive(Default)]
struct Fnv(u64);
impl std::hash::Hasher for Fnv {
    fn finish(&self) -> u64 { self.0 }
    fn write(&mut self, bytes: &[u8]) {
        let mut h = if self.0 == 0 { 0xcbf29ce484222325 } else { self.0 };
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        self.0 = h;
    }
}

fn printable(b: u8) -> bool { (33..=126).contains(&b) }

fn flat_index(sym: &[u8]) -> usize {
    let c = |b: u8| (b - 33) as usize;
    match sym.len() {
        1 => c(sym[0]),
        2 => 94 + c(sym[0]) * 94 + c(sym[1]),
        _ => 94 + 94 * 94 + (c(sym[0]) * 94 + c(sym[1])) * 94 + c(sym[2]),
    }
}

impl SymTab {
    fn new(symbols: &[Vec<u8>]) -> SymTab {
        let mut tab = SymTab { flat: vec![NONE; 94 + 94 * 94 + 94 * 94 * 94], rest: Default::default() };
        for (i, sym) in symbols.iter().enumerate() {
            if sym.len() >= 1 && sym.len() <= 3 && sym.iter().all(|&b| printable(b)) {
                tab.flat[flat_index(sym)] = i as u32;
            } else {
                tab.rest.insert(sym.clone(), i as u32);
            }
        }
        tab
    }
    fn lookup(&self, sym: &[u8]) -> Option<u32> {
        if sym.len() >= 1 && sym.len() <= 3 && sym.iter().all(|&b| printable(b)) {
            match self.flat[flat_index(sym)] { NONE => None, o => Some(o) }
        } else {
            self.rest.get(sym).copied()
        }
    }
}

// -- tokenizer -------------------------------------------------------------

/// Handle to a just-returned token. Valid until the next next_token().
#[derive(Copy, Clone)]
struct TokRef { start: usize, len: usize, off: u64, assembled: bool }

struct Tokenizer {
    file: File,
    buf: Vec<u8>,
    fill: usize,
    pos: usize,
    base: u64, // absolute offset of buf[0]
    end: u64,  // absolute offset one past the last byte of THIS range
    eof: bool,
    spill: Vec<u8>,     // token bytes carried across a refill
    spill_off: u64,
    assembled: Vec<u8>, // reassembled token (spill + buffer part)
    max_token_len: usize,
}

impl Tokenizer {
    fn new(mut file: File, start: u64, end: u64, max_token_len: usize) -> Result<Tokenizer, String> {
        file.seek(SeekFrom::Start(start)).map_err(|e| format!("seek to data start: {}", e))?;
        Ok(Tokenizer {
            file, buf: vec![0; READ_CHUNK], fill: 0, pos: 0, base: start, end,
            eof: false, spill: Vec::new(), spill_off: 0, assembled: Vec::new(),
            max_token_len,
        })
    }

    fn refill(&mut self) -> Result<(), String> {
        self.base += self.fill as u64;
        self.pos = 0;
        // Never read past the range end: a worker stops exactly at its
        // split point so the next worker owns the bytes beyond it.
        let cap = ((self.end - self.base) as usize).min(self.buf.len());
        match self.file.read(&mut self.buf[..cap]) {
            // fill MUST be cleared on EOF: a stale fill would re-tokenize
            // the old buffer contents under an advanced base.
            Ok(0) => { self.eof = true; self.fill = 0; }
            Ok(n) => self.fill = n,
            Err(e) => die!("read error: {}", e),
        }
        Ok(())
    }

    fn next_token(&mut self) -> Result<Option<TokRef>, String> {
        loop {
            // Leading whitespace terminates an in-flight spill token, so
            // only skip it when no spill is pending.
            while self.spill.is_empty() && self.pos < self.fill && is_ws(self.buf[self.pos]) {
                self.pos += 1;
            }
            if self.pos == self.fill {
                if self.eof {
                    return Ok(self.take_spill());
                }
                self.refill()?;
                continue;
            }
            let start = self.pos;
            while self.pos < self.fill && !is_ws(self.buf[self.pos]) {
                self.pos += 1;
            }
            if self.pos < self.fill || self.eof {
                // Token terminated by whitespace (or EOF): complete.
                if self.spill.is_empty() {
                    if self.pos - start > self.max_token_len {
                        die!("VCD token exceeds {} characters", self.max_token_len);
                    }
                    return Ok(Some(TokRef {
                        start, len: self.pos - start,
                        off: self.base + start as u64, assembled: false,
                    }));
                }
                self.spill.extend_from_slice(&self.buf[start..self.pos]);
                return Ok(Some(self.finish_spill()?));
            }
            // Token runs into the buffer end with more file to read: stash.
            if self.spill.is_empty() {
                self.spill_off = self.base + start as u64;
            }
            self.spill.extend_from_slice(&self.buf[start..self.pos]);
            if self.spill.len() > self.max_token_len {
                die!("VCD token exceeds {} characters", self.max_token_len);
            }
            self.refill()?;
        }
    }

    fn take_spill(&mut self) -> Option<TokRef> {
        if self.spill.is_empty() { return None; }
        match self.finish_spill() {
            Ok(t) => Some(t),
            Err(_) => None, // length cap cannot fail here (checked at stash)
        }
    }

    fn finish_spill(&mut self) -> Result<TokRef, String> {
        if self.spill.len() > self.max_token_len {
            die!("VCD token exceeds {} characters", self.max_token_len);
        }
        let off = self.spill_off;
        self.assembled = std::mem::take(&mut self.spill);
        Ok(TokRef { start: 0, len: self.assembled.len(), off, assembled: true })
    }

    fn bytes(&self, t: TokRef) -> &[u8] {
        if t.assembled { &self.assembled } else { &self.buf[t.start..t.start + t.len] }
    }
}

// -- classification (pure; runs while the token bytes are borrowed) --------

#[derive(Copy, Clone)]
enum Class {
    MarkerKnown, // '$end' / $dump*: item, no state change
    SectionOpen, // any other $X: item, body drained to $end
    Time(u64),   // timestamp item
    TimeBad,     // '#'-opener failing int(): tolerated skip item
    ScalarVal,   // 0/1/x/z/X/Z + identifier
    BOpen,
    ROpen,
    POpen,
    Other,       // everything else: item with no state effect
}

fn classify(b: &[u8]) -> Result<Class, String> {
    let first = b[0];
    // Python's int() and the _REAL_RE regex accept non-ASCII digits; this
    // builder is ASCII-only. Refusal is needed ONLY where a divergence is
    // possible: '#' (int() takes Unicode digits) and r/R (\d in the real
    // regex). b/B values must NOT be scanned — they can be 512+ bytes and
    // a non-ASCII byte there takes the IDENTICAL invalid-4-state drop path
    // in both implementations (is_4state_bits vs _DEL_4STATE_CI), so there
    // is no divergence to refuse; scanning them cost ~0.6 s on a 10 GiB
    // bus-heavy dump (review round 3, perf follow-up). Scalar and p tokens
    // are likewise parity-safe without a scan (byte-exact identifier
    // lookup; fixed ASCII state/level sets on both sides).
    if matches!(first, b'#' | b'r' | b'R')
        && b.iter().any(|&c| c >= 0x80)
    {
        die!("non-ASCII byte in a numeric grammar token; use the pure-Python builder");
    }
    if first == b'$' {
        return Ok(if is_known_marker(b) { Class::MarkerKnown } else { Class::SectionOpen });
    }
    if first == b'#' {
        if b.len() > 1 && b[1].is_ascii_digit() {
            return Ok(match parse_int(b)? { Some(v) => Class::Time(v), None => Class::TimeBad });
        }
        return Ok(Class::Other); // '#x' / bare '#': value/marker fall-through
    }
    if b.len() > 1 {
        match first {
            b'0' | b'1' | b'x' | b'X' | b'z' | b'Z' => return Ok(Class::ScalarVal),
            b'b' | b'B' => return Ok(Class::BOpen),
            b'r' | b'R' => return Ok(Class::ROpen),
            b'p' => return Ok(Class::POpen),
            _ => {}
        }
    }
    Ok(Class::Other)
}

fn is_known_marker(b: &[u8]) -> bool {
    matches!(
        b,
        b"$end" | b"$dumpall" | b"$dumpoff" | b"$dumpon" | b"$dumpvars" | b"$dumpports"
            | b"$dumpportsoff" | b"$dumpportson" | b"$dumpportsall"
    )
}

/// Python int(tok[1:]): digits, single underscores between digit runs only.
/// None = malformed (tolerated skip); Err = fatal (length / int64 caps).
/// Known divergence: Python's int() also accepts non-ASCII digits; this
/// parser is deliberately ASCII-only (see the mirror note in index.py).
fn parse_int(tok: &[u8]) -> Result<Option<u64>, String> {
    let body = &tok[1..];
    if body.len() > 100 {
        die!("VCD timestamp token too long (>100 digits)");
    }
    let mut t: u64 = 0;
    let mut any = false;
    let mut prev_us = true;
    for &b in body {
        if b.is_ascii_digit() {
            t = match t.checked_mul(10).and_then(|v| v.checked_add((b - b'0') as u64)) {
                Some(v) if v <= i64::MAX as u64 => v,
                _ => die!("VCD timestamp too large (int64)"),
            };
            any = true;
            prev_us = false;
        } else if b == b'_' {
            if prev_us { return Ok(None); }
            prev_us = true;
        } else {
            return Ok(None);
        }
    }
    if !any || prev_us { return Ok(None); }
    Ok(Some(t))
}

fn is_4state_bits(bits: &[u8]) -> bool {
    !bits.is_empty() && bits.iter().all(|&b| matches!(b, b'0' | b'1' | b'x' | b'X' | b'z' | b'Z'))
}

/// IEEE %g real_number (vcd_analyzer._REAL_RE).
fn is_real(body: &[u8]) -> bool {
    let mut s = body;
    if matches!(s.first(), Some(&b'+') | Some(&b'-')) { s = &s[1..]; }
    let int_digits = s.iter().take_while(|&&b| b.is_ascii_digit()).count();
    if int_digits == 0 {
        if !matches!(s.first(), Some(&b'.')) { return false; }
        s = &s[1..];
        if !matches!(s.first(), Some(b) if b.is_ascii_digit()) { return false; }
        while matches!(s.first(), Some(b) if b.is_ascii_digit()) { s = &s[1..]; }
    } else {
        s = &s[int_digits..];
        if matches!(s.first(), Some(&b'.')) {
            s = &s[1..];
            while matches!(s.first(), Some(b) if b.is_ascii_digit()) { s = &s[1..]; }
        }
    }
    match s.first() {
        None => true,
        Some(&b'e') | Some(&b'E') => {
            s = &s[1..];
            if matches!(s.first(), Some(&b'+') | Some(&b'-')) { s = &s[1..]; }
            !s.is_empty() && s.iter().all(|b| b.is_ascii_digit())
        }
        _ => false,
    }
}

/// inf/infinity/nan(payload) forms (vcd_analyzer._REAL_NONFINITE_RE).
fn is_nonfinite(body: &[u8]) -> bool {
    let mut s = body;
    if matches!(s.first(), Some(&b'+') | Some(&b'-')) { s = &s[1..]; }
    let lower = s.to_ascii_lowercase();
    if lower.starts_with(b"nan") {
        let rest = &lower[3..];
        if rest.is_empty() { return true; }
        return rest.len() >= 3
            && rest[0] == b'('
            && rest[rest.len() - 1] == b')'
            && rest[1..rest.len() - 1].iter().all(|&b| b != b'(' && b != b')' && !is_ws(b));
    }
    if lower.starts_with(b"inf") {
        let rest = &lower[3..];
        return rest.is_empty() || rest == b"inity";
    }
    false
}

fn port_state_ok(state: &[u8]) -> bool {
    const OK: &[u8] = b"DUNZduLHXThl01?FAaBbCcf";
    !state.is_empty() && state.iter().all(|&b| OK.contains(&b))
}

fn strength_ok(tok: &[u8]) -> bool {
    tok.len() == 1 && (b'0'..=b'7').contains(&tok[0])
}

// -- builder ---------------------------------------------------------------

struct Builder {
    tok: Tokenizer,
    symtab: SymTab,
    pending: VecDeque<(Vec<u8>, u64)>, // pushed-back items (rare; owned)
    current: u64,
    block_start: u64,
    block_initial: u64,
    blocks: Vec<(u64, u64, u64, u64)>,
    recent_pos: Vec<u64>,
    touched: Vec<u32>,
    postings: Vec<Vec<(u32, u32)>>,
    block_bytes: u64,
    max_block_bytes: u64,
    first_time: Option<u64>,
    saw_opener: bool,
}

impl Builder {
    fn note(&mut self, ord: u32, position: u64) {
        if self.recent_pos[ord as usize] == u64::MAX {
            self.touched.push(ord);
        }
        self.recent_pos[ord as usize] = position;
    }

    /// Close the current block at `position` (Python flush()).
    fn flush(&mut self, end: u64) -> Result<(), String> {
        if end <= self.block_start { return Ok(()); }
        let bid = self.blocks.len() as u32;
        let bytes = end - self.block_start;
        if bytes > self.max_block_bytes { self.max_block_bytes = bytes; }
        self.blocks.push((self.block_start, end, self.block_initial, self.current));
        let start = self.block_start;
        let mut i = 0;
        while i < self.touched.len() {
            let ord = self.touched[i];
            let pos = self.recent_pos[ord as usize];
            if pos != u64::MAX {
                let rel = pos - start;
                if rel > u32::MAX as u64 {
                    die!("record offset {} within a block exceeds u32", rel);
                }
                self.postings[ord as usize].push((bid, rel as u32));
                self.recent_pos[ord as usize] = u64::MAX;
                self.touched.swap_remove(i);
            } else {
                i += 1;
            }
        }
        self.block_start = end;
        self.block_initial = self.current;
        Ok(())
    }

    fn item_boundary(&mut self, position: u64) -> Result<(), String> {
        if position - self.block_start >= self.block_bytes {
            self.flush(position)?;
        }
        Ok(())
    }

    /// Operand fetch for b/r/p identifiers. None when structural (pushed
    /// back onto pending) or at EOF.
    fn take_operand(&mut self) -> Result<Option<TokRef>, String> {
        let t = match self.tok.next_token()? { Some(t) => t, None => return Ok(None) };
        let structural = {
            let b = self.tok.bytes(t);
            b.len() > 1 && b[0] == b'#' && b[1].is_ascii_digit()
                && self.symtab.lookup(b).is_none()
        };
        if structural {
            let owned = self.tok.bytes(t).to_vec();
            self.pending.push_back((owned, t.off));
            return Ok(None);
        }
        Ok(Some(t))
    }

    /// Drain a '$X ... $end' section body; body tokens are not items.
    fn drain_section(&mut self) -> Result<(), String> {
        while let Some(t) = self.tok.next_token()? {
            if self.tok.bytes(t) == b"$end" { break; }
        }
        Ok(())
    }

    fn note_time(&mut self, t: u64) {
        if self.first_time.is_none() {
            self.first_time = Some(t);
        }
        self.current = t;
    }

    fn run(&mut self, end_of_data: u64) -> Result<(), String> {
        let debug = std::env::var("VCDIDX_DEBUG").is_ok();
        loop {
            while let Some((v, off)) = self.pending.pop_front() {
                if debug { eprintln!("item pending {:?} @{}", String::from_utf8_lossy(&v), off); }
                self.apply_pending(&v, off)?;
            }
            let t = match self.tok.next_token()? { Some(t) => t, None => break };
            if debug {
                eprintln!("item {:?} @{} cur={}", String::from_utf8_lossy(self.tok.bytes(t)), t.off, self.current);
            }
            self.item_boundary(t.off)?;
            let class = classify(self.tok.bytes(t))?;
            self.apply_fresh(t, class)?;
        }
        self.flush(end_of_data)?;
        Ok(())
    }

    /// Pushed-back items are only '#<digits>' tokens (structural operands)
    /// or single strength digits — timestamps or no-ops in item position.
    fn apply_pending(&mut self, v: &[u8], off: u64) -> Result<(), String> {
        self.item_boundary(off)?;
        if let Class::Time(tv) = classify(v)? {
            if tv < self.current {
                die!("non-monotonic timestamps: index requires fallback");
            }
            self.note_time(tv);
        }
        Ok(())
    }

    fn apply_fresh(&mut self, t: TokRef, class: Class) -> Result<(), String> {
        match class {
            Class::MarkerKnown => {}
            Class::SectionOpen => {
                // A section opener means byte-level split anchors may not
                // be top-level: the merge falls back to a single-threaded
                // rebuild when any worker saw one (zero extra I/O — the
                // worker parses every byte anyway).
                self.saw_opener = true;
                self.drain_section()?;
            }
            Class::Time(v) => {
                if v < self.current {
                    die!("non-monotonic timestamps: index requires fallback");
                }
                self.note_time(v);
            }
            Class::TimeBad | Class::Other => {}
            Class::ScalarVal => {
                let bytes = self.tok.bytes(t);
                let ord = self.symtab.lookup(&bytes[1..]);
                if let Some(o) = ord {
                    self.note(o, t.off);
                }
            }
            Class::BOpen => {
                let valid = is_4state_bits(&self.tok.bytes(t)[1..]);
                if let Some(op) = self.take_operand()? {
                    if valid {
                        if let Some(o) = self.symtab.lookup(self.tok.bytes(op)) {
                            self.note(o, t.off);
                        }
                    }
                }
            }
            Class::ROpen => {
                let valid = {
                    let b = self.tok.bytes(t);
                    b.len() <= 64 && (is_real(&b[1..]) || is_nonfinite(&b[1..]))
                };
                if let Some(op) = self.take_operand()? {
                    if valid {
                        if let Some(o) = self.symtab.lookup(self.tok.bytes(op)) {
                            self.note(o, t.off);
                        }
                    }
                }
            }
            Class::POpen => {
                let valid = port_state_ok(&self.tok.bytes(t)[1..]);
                if !valid {
                    // Python validates the state before consuming anything.
                    return Ok(());
                }
                // s0/s1: plain token fetch, NO structural rule (Python).
                // Strengths are OWNED immediately: a later next_token() may
                // refill the shared buffer and invalidate any TokRef into
                // it (review P1-3).
                let s0 = match self.tok.next_token()? {
                    Some(s) => {
                        let owned = self.tok.bytes(s).to_vec();
                        if !strength_ok(&owned) {
                            self.pending.push_front((owned, s.off));
                            return Ok(());
                        }
                        (owned, s.off)
                    }
                    None => return Ok(()),
                };
                let s1 = match self.tok.next_token()? {
                    Some(s) => {
                        let owned = self.tok.bytes(s).to_vec();
                        if !strength_ok(&owned) {
                            // Python pop order is s0, s1: front-push s1
                            // first so s0 ends up in front.
                            self.pending.push_front((owned, s.off));
                            self.pending.push_front(s0.clone());
                            return Ok(());
                        }
                        (owned, s.off)
                    }
                    None => return Ok(()),
                };
                match self.take_operand()? {
                    Some(op) => {
                        if let Some(o) = self.symtab.lookup(self.tok.bytes(op)) {
                            self.note(o, t.off);
                        }
                    }
                    None => {
                        // Python pop order is s0, s1, structural; the
                        // structural token is already at the BACK (pushed
                        // by take_operand), so front-push s1 then s0.
                        self.pending.push_front(s1.clone());
                        self.pending.push_front(s0.clone());
                    }
                }
            }
        }
        Ok(())
    }
}

// -- core entry ------------------------------------------------------------

/// Build the sidecar. Returns the stats JSON on success (same fields the
/// standalone binary prints), or a human-readable error message.
pub fn build_from_manifest(
    manifest_text: &str,
    vcd_path: &str,
    sidecar_path: &str,
) -> Result<String, String> {
    let started = Instant::now();
    let mut lines = manifest_text.lines().filter(|l| !l.is_empty());
    let mut next_num = |name: &str| -> Result<u64, String> {
        let line = match lines.next() {
            Some(l) => l,
            None => die!("manifest: missing {}", name),
        };
        let mut it = line.split_whitespace();
        let key = it.next().unwrap_or("");
        let val = match it.next() { Some(v) => v, None => die!("manifest: bad {}", name) };
        if key != name {
            die!("manifest: expected {} got {}", name, key);
        }
        val.parse::<u64>().map_err(|_| format!("manifest: {} not a number", name))
    };
    let data_start = next_num("data_start")?;
    let block_bytes = next_num("block_bytes")?;
    let max_token_len = next_num("max_token_len")? as usize;
    let sym_count = next_num("symbols")? as usize;
    if block_bytes == 0 || block_bytes > (4096u64 << 20) {
        die!("block_bytes must be between 1 MiB-equivalent and 4096 MiB (u32 offsets)");
    }
    let mut symbols: Vec<Vec<u8>> = Vec::with_capacity(sym_count);
    while symbols.len() < sym_count {
        match lines.next() {
            Some(line) => symbols.push(line.as_bytes().to_vec()),
            None => die!("manifest: symbol lines short"),
        }
    }

    let meta = File::open(vcd_path).and_then(|f| f.metadata())
        .map_err(|e| format!("stat: {}", e))?;
    let size0 = meta.len();
    let mtime0 = meta.modified().ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);

    // -- thread plan --------------------------------------------------------
    // The scan is single-threaded by default on small files; on big ones the
    // data section is split at TIMESTAMP boundaries and parsed by up to
    // VCD_ANALYZER_INDEX_THREADS workers (default: min(4, cores)). A '#T'
    // split point is always equivalent to the sequential scan: the token
    // before it either completes a record (workers agree) or is an opener
    // whose operand is that '#T' — structurally consumed and dropped in
    // BOTH executions, with the '#T' then read as a timestamp. Per-block
    // postings depend only on the bytes inside the block, so merged results
    // are identical up to block-grid placement (queries don't care).
    let threads_env = std::env::var("VCD_ANALYZER_INDEX_THREADS").ok()
        .and_then(|v| v.trim().parse::<usize>().ok()).unwrap_or(0);
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let threads = if threads_env == 0 { cores.min(4) } else { threads_env.min(16) };
    let parallel_min = std::env::var("VCD_ANALYZER_INDEX_PARALLEL_MIN").ok()
        .and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(64 << 20);

    let symtab = SymTab::new(&symbols);
    let mut splits: Vec<u64> = vec![data_start];
    if threads > 1 && size0.saturating_sub(data_start) >= parallel_min {
        for i in 1..threads {
            let nominal = data_start + (size0 - data_start) * (i as u64) / threads as u64;
            let last = *splits.last().unwrap();
            if nominal <= last + (16 << 20) || nominal + (16 << 20) >= size0 {
                continue; // keep chunks meaty; fewer workers is fine
            }
            match find_timestamp_split(vcd_path, nominal, size0, &symtab)? {
                Some((off, _time)) if off > last + (16 << 20) && off + (16 << 20) < size0 => {
                    splits.push(off)
                }
                _ => {}
            }
        }
    }
    splits.push(size0);

    struct WorkerOut {
        blocks: Vec<(u64, u64, u64, u64)>,
        postings: Vec<Vec<(u32, u32)>>,
        first_time: Option<u64>,
        last_time: u64,
        max_block_bytes: u64,
        saw_opener: bool,
    }

    let parse = |start: u64, end: u64| -> Result<WorkerOut, String> {
        let file = File::open(vcd_path).map_err(|e| format!("open: {}", e))?;
        let mut b = Builder {
            tok: Tokenizer::new(file, start, end, max_token_len)?,
            symtab: SymTab::new(&symbols),  // cheap: 3.4 MB flat table per worker
            pending: VecDeque::new(),
            current: 0,
            block_start: start,
            block_initial: 0,
            blocks: Vec::new(),
            recent_pos: vec![u64::MAX; symbols.len()],
            touched: Vec::new(),
            postings: vec![Vec::new(); symbols.len()],
            block_bytes,
            max_block_bytes: 0,
            first_time: None,
            saw_opener: false,
        };
        b.run(end)?;
        Ok(WorkerOut {
            first_time: b.first_time,
            blocks: b.blocks,
            postings: b.postings,
            last_time: b.current,
            max_block_bytes: b.max_block_bytes,
            saw_opener: b.saw_opener,
        })
    };

    let mut workers: Vec<WorkerOut> = Vec::with_capacity(splits.len() - 1);
    if splits.len() == 2 {
        workers.push(parse(data_start, size0)?);
    } else {
        let ranges: Vec<(u64, u64)> = splits.windows(2).map(|w| (w[0], w[1])).collect();
        let outs: Vec<Result<WorkerOut, String>> = Vec::new();
        let mut outs = outs;
        std::thread::scope(|scope| {
            let handles: Vec<_> = ranges.iter().map(|&(s, e)| {
                scope.spawn(move || parse(s, e))
            }).collect();
            for h in handles {
                outs.push(h.join().unwrap_or_else(|_| Err("worker panicked".to_string())));
            }
        });
        workers = outs.into_iter().collect::<Result<Vec<_>, String>>()?;
    }
    // Soundness gate AFTER the fact (review F4, v2): byte-level split
    // anchors cannot know grammar context — a '#T' inside a $comment body
    // that spans a split point would be misread as a timestamp by the
    // worker starting there. Workers parse every byte anyway, so each
    // simply reports whether it saw a section opener; if any did, the
    // parallel result is discarded and the fully context-aware
    // single-threaded parse runs instead. Files without section openers
    // (the common huge dump) keep the full parallel speed with ZERO extra
    // I/O — no pre-scan.
    if workers.iter().any(|w| w.saw_opener) && splits.len() > 2 {
        workers.clear();
        workers.push(parse(data_start, size0)?);
    }

    // -- merge ---------------------------------------------------------------
    let mut blocks: Vec<(u64, u64, u64, u64)> = Vec::new();
    let mut postings: Vec<Vec<(u32, u32)>> = vec![Vec::new(); symbols.len()];
    let mut max_block_bytes: u64 = 0;
    let mut carried_time: u64 = 0; // time established before the current worker
    for w in workers {
        if let Some(ft) = w.first_time {
            if ft < carried_time {
                die!("non-monotonic timestamps: index requires fallback");
            }
        }
        // The worker's first block opens at its range start; the time in
        // effect there is whatever the previous workers established. Later
        // blocks inherit the previous block's t1, as in the sequential scan.
        for (bi, &(s, e, _t0, t1)) in w.blocks.iter().enumerate() {
            let t0 = if bi == 0 { carried_time } else { w.blocks[bi - 1].3 };
            blocks.push((s, e, t0, t1));
        }
        let base_bid = (blocks.len() - w.blocks.len()) as u32;
        for (sym, plist) in w.postings.into_iter().enumerate() {
            let target = &mut postings[sym];
            target.reserve(plist.len());
            for (bid, off) in plist {
                target.push((bid + base_bid, off));
            }
        }
        max_block_bytes = max_block_bytes.max(w.max_block_bytes);
        if !w.blocks.is_empty() {
            carried_time = w.last_time;
        }
    }
    // Defense in depth (review P0-1): a corrupt merge must fail the build,
    // never write a sidecar whose block times a reader would mis-bisect.
    for window in blocks.windows(2) {
        if window[0].3 > window[1].3 {
            die!("internal error: block time regression after merge");
        }
    }

    let meta1 = File::open(vcd_path).and_then(|f| f.metadata())
        .map_err(|e| format!("stat: {}", e))?;
    let mtime1 = meta1.modified().ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    if meta1.len() != size0 || mtime1 != mtime0 {
        die!("source changed while building index");
    }

    let nblocks = blocks.len();
    let narrow = nblocks <= 65535;
    let mode: u32 = if narrow { 2 } else { 0 };
    let entry_bytes: u64 = if narrow { 6 } else { 8 };
    let pairs: u64 = postings.iter().map(|p| p.len() as u64).sum();
    // header ('8s' magic + 6 u64) = 56; BLOCK = 32; DIRECTORY = 16
    let directory_bytes = 56 + 32 * nblocks as u64 + 16 * symbols.len() as u64;

    // Publish atomically (review P0-2): a concurrent reader must never mmap
    // a half-written sidecar, and the fresh-claiming header is written first
    // — an interrupted in-place write would look valid forever.
    let tmp_path = format!("{}.tmp.{}", sidecar_path, std::process::id());
    let threads_used = splits.len() - 1;
    let out = File::create(&tmp_path).map_err(|e| format!("create sidecar: {}", e))?;
    // Builder-owned cleanup (review finding C): the temp file is removed
    // unless the rename below publishes it.
    struct TempGuard<'a> { path: &'a str, armed: bool }
    impl Drop for TempGuard<'_> {
        fn drop(&mut self) {
            if self.armed {
                let _ = std::fs::remove_file(self.path);
            }
        }
    }
    let mut guard = TempGuard { path: &tmp_path, armed: true };
    let mut w = BufWriter::with_capacity(1 << 20, out);
    let io = |e: std::io::Error| format!("write: {}", e);
    w.write_all(b"VCDIDX02").map_err(io)?;
    put_u64(&mut w, size0)?;
    put_u64(&mut w, mtime0)?;
    put_u64(&mut w, block_bytes)?;
    put_u64(&mut w, nblocks as u64)?;
    put_u64(&mut w, symbols.len() as u64)?;
    put_u64(&mut w, data_start)?;
    for &(s, e, t0, t1) in &blocks {
        put_u64(&mut w, s)?;
        put_u64(&mut w, e)?;
        put_u64(&mut w, t0)?;
        put_u64(&mut w, t1)?;
    }
    let mut location = directory_bytes;
    for p in &postings {
        put_u64(&mut w, location)?;
        put_u32(&mut w, p.len() as u32)?;
        put_u32(&mut w, mode)?;
        location += p.len() as u64 * entry_bytes;
    }
    for p in &postings {
        for &(bid, rel) in p {
            if narrow {
                put_u16(&mut w, bid as u16)?;
                put_u32(&mut w, rel)?;
            } else {
                put_u32(&mut w, bid)?;
                put_u32(&mut w, rel)?;
            }
        }
    }
    w.flush().map_err(io)?;
    drop(w);
    std::fs::rename(&tmp_path, sidecar_path).map_err(|e| format!("publish sidecar: {}", e))?;
    guard.armed = false;
    let index_bytes = std::fs::metadata(sidecar_path).map(|m| m.len()).unwrap_or(0);

    Ok(format!(
        "{{\"build_s\":{:.4},\"source_bytes\":{},\"index_bytes\":{},\"blocks\":{},\"raw_symbols\":{},\"signal_block_pairs\":{},\"max_block_bytes\":{},\"posting_mode\":{},\"threads\":{}}}",
        started.elapsed().as_secs_f64(), size0, index_bytes, nblocks,
        symbols.len(), pairs, max_block_bytes, mode, threads_used
    ))
}

fn put_u16(w: &mut BufWriter<File>, v: u16) -> Result<(), String> { w.write_all(&v.to_le_bytes()).map_err(|e| format!("write: {}", e)) }
fn put_u32(w: &mut BufWriter<File>, v: u32) -> Result<(), String> { w.write_all(&v.to_le_bytes()).map_err(|e| format!("write: {}", e)) }
fn put_u64(w: &mut BufWriter<File>, v: u64) -> Result<(), String> { w.write_all(&v.to_le_bytes()).map_err(|e| format!("write: {}", e)) }

// -- C ABI for ctypes ------------------------------------------------------

use std::ffi::CStr;

pub const ABI_VERSION: c_uint = 1;

fn write_cstr(dst: *mut c_char, cap: usize, text: &str) {
    if dst.is_null() || cap == 0 { return; }
    let bytes = text.as_bytes();
    let n = bytes.len().min(cap - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dst as *mut u8, n);
        *dst.add(n) = 0;
    }
}

/// ABI version of the library; callers refuse mismatched values.
#[no_mangle]
pub extern "C" fn vcdidx_abi_version() -> c_uint {
    ABI_VERSION
}

/// Build a sidecar. Buffers are caller-allocated, NUL-terminated outputs;
/// manifest is (ptr, len) so it may contain any bytes. Returns 0 on
/// success (stats_out holds the stats JSON), 2 on failure (err_out holds
/// the message), 3 on bad pointer arguments.
#[no_mangle]
pub extern "C" fn vcdidx_abi_build(
    manifest: *const c_char,
    manifest_len: usize,
    vcd: *const c_char,
    sidecar: *const c_char,
    err_out: *mut c_char,
    err_len: usize,
    stats_out: *mut c_char,
    stats_len: usize,
) -> c_int {
    if manifest.is_null() || vcd.is_null() || sidecar.is_null() {
        write_cstr(err_out, err_len, "vcdidx: null pointer argument");
        return 3;
    }
    let manifest_text = unsafe {
        String::from_utf8_lossy(std::slice::from_raw_parts(manifest as *const u8, manifest_len))
            .into_owned()
    };
    let vcd_text = unsafe { CStr::from_ptr(vcd).to_string_lossy().into_owned() };
    let sidecar_text = unsafe { CStr::from_ptr(sidecar).to_string_lossy().into_owned() };
    match build_from_manifest(&manifest_text, &vcd_text, &sidecar_text) {
        Ok(stats) => { write_cstr(stats_out, stats_len, &stats); 0 }
        Err(e) => { write_cstr(err_out, err_len, &e); 2 }
    }
}

// -- parallel split points --------------------------------------------------

/// First '#<digits>' token boundary at or after `nominal`. Splitting at a
/// timestamp token is always equivalent to the sequential scan (see the
/// thread-plan comment in build_from_manifest). None when no timestamp is
/// found within a growing window (caller falls back to fewer workers).
fn find_timestamp_split(
    vcd_path: &str,
    nominal: u64,
    file_end: u64,
    symtab: &SymTab,
) -> Result<Option<(u64, u64)>, String> {
    let mut f = File::open(vcd_path).map_err(|e| format!("open: {}", e))?;
    let mut window: usize = 256 << 10;
    while window <= (32 << 20) {
        if nominal >= file_end {
            return Ok(None);
        }
        let cap = (window as u64).min(file_end - nominal) as usize;
        let mut buf = vec![0u8; cap];
        f.seek(SeekFrom::Start(nominal)).map_err(|e| format!("seek: {}", e))?;
        let mut got = 0usize;
        while got < cap {
            match f.read(&mut buf[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => die!("read: {}", e),
            }
        }
        if got == 0 {
            return Ok(None);
        }
        buf.truncate(got);
        let mut i = 0usize;
        // the first token may be partial (nominal can land mid-token): skip it
        let mut skipped = false;
        while i < got {
            if is_ws(buf[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < got && !is_ws(buf[i]) {
                i += 1;
            }
            if !skipped {
                skipped = true; // partial first token, not trustworthy
                continue;
            }
            let tok = &buf[start..i];
            // Only a timestamp that FULLY parses may anchor a split: a
            // malformed '#1.5' would be skipped by the workers' parser
            // (Python's tolerant-reader policy), leaving that worker with
            // no established time and zero block times (review P0-1). A
            // token that is a DECLARED identifier (legal per IEEE 1364
            // 18.2.1) may be a b/r/p operand in the sequential scan, so it
            // must not be treated as a boundary either (review P2-7).
            if tok.len() > 1 && tok[0] == b'#' && tok[1].is_ascii_digit() {
                if symtab.lookup(tok).is_none() {
                    if let Some(tv) = parse_int_bytes(tok)? {
                        // token must be complete: it ended at whitespace
                        // (or EOF), never at the window edge
                        if i < got || got < cap {
                            return Ok(Some((nominal + start as u64, tv)));
                        }
                    }
                }
            }
        }
        window *= 2;
    }
    Ok(None)
}

/// parse_int over a bare token (no leading '#' skip difference).
fn parse_int_bytes(tok: &[u8]) -> Result<Option<u64>, String> {
    parse_int(tok)
}
