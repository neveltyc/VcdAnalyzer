#!/usr/bin/env python3
"""VCD waveform analyzer for Agent-based RTL debug.

Usage: vcd_analyzer [--json] <command> <file> [options]

Commands:
  info       <file>                               File overview (timescale, signal count, time span, scopes)
  list       <file> [--filter K1,K2]               List signals with path and bit width
  dump       <file> [--begin T] [--end T] [--filter K1,K2]   Print signal value changes in time order
  summary    <file> [--begin T] [--end T] [--filter K1,K2]   Per-signal stats: change count, unique values, static detection
  snapshot   <file> --at T [--filter K1,K2]        Known signal values at a given time point
  compare    <file> --at T1,T2 [--filter K1,K2]    Diff signal values between two time points
  search     <file> --condition C [--condition C ...] [--show K1,K2] [--begin T] [--end T]
                                                        Conditional search and associated signal observation

Global options:
  --json       Output compact structured JSON instead of text (time fields include *_ticks)
  --limit N    Max rows/records to emit; default 500; 0 = unlimited.
               Streaming commands stop after detecting the first unshown result.
  --verbose    Show extra fields; if --limit is omitted, disables truncation

Argument formats:
  <file>          VCD file path
  --filter K1,K2  Comma-separated patterns. Plain text uses case-insensitive substring match;
                  patterns containing * or ? use case-insensitive glob match.
                  e.g. --filter clk,rst   --filter '*_valid,*_ready,*_data'   --filter 'top.u_dma.*'
  --begin T       Start time with optional unit suffix: 0, 100ns, 17.5us, 1ms, 500ps, 200fs
  --end T         End time, same format as --begin. Omit for no upper bound
  --at T          Time point for snapshot. For compare: two points comma-separated: --at 17.5us,17.7us
  --condition C   One comma-separated AND clause. Each term is a level comparison
                  (SIG=VAL, SIG==VAL, SIG!=VAL) or the edge predicate changed(SIG).
                  Condition signal patterns must match exactly one signal.
                  SIG!=VAL does not match x/z/undef; use SIG=x to search unknown.
                  Values: decimal 5, hex 0x5, binary b0101, 4-state b1x0z, real 3.14.
                  '?' in a binary literal is a don't-care bit: status=b?????1?? tests bit 2
                  of an 8-bit bus (a short literal pads with 0, so write every bit).
                  A negative decimal (-5) on a logic signal means its two's-complement
                  bit pattern in the declared width (cnt=-1 on 32 bits = 0xffffffff).
                  A logic signal takes bit/numeric targets, a real signal numeric ones;
                  an event variable has no level -- ask changed(SIG) instead.
                  REPEAT the flag to OR the clauses (OR-of-ANDs): the search holds
                  wherever ANY clause holds, e.g. one clause per channel to find when
                  any handshakes. There is no in-string OR ('|' / 'OR' / parentheses).
  --show K1,K2    Optional associated signals to display while condition holds;
                  segment mode splits whenever shown values change.

  changed(SIG)    An edge predicate term, true at exactly the ticks where SIG
                  transitions. It switches search to event mode (instants, not
                  intervals); every clause must then carry one, or none may.
                  First observed values and t=0 initialization are not transitions;
                  VCD event variables count each trigger. With no --show, event
                  mode shows the changed() signals.
                  changed(a),changed(b) requires both to transition on one tick.
                  Level terms in the clause read the tick's SETTLED state, so the
                  answer does not depend on the order same-tick records happen to
                  be written in; the transitioning signal itself reads the value it
                  took AT that edge, so "changed(s),s=1" means "rising edge of s".

Examples:
  vcd_analyzer info sim.vcd
  vcd_analyzer list sim.vcd --filter tdata,tvalid,tready
  vcd_analyzer dump sim.vcd --begin 17.5us --end 17.6us --filter clk,rst,state
  vcd_analyzer summary sim.vcd --filter dll_st,locked
  vcd_analyzer snapshot sim.vcd --at 17.55us --filter init_done,state
  vcd_analyzer compare sim.vcd --at 17.535us,17.56us --filter init_done,link_active,state
  vcd_analyzer search sim.vcd --condition "state=5"
  vcd_analyzer search sim.vcd --condition "arvalid=1,arready=1" --show araddr,arlen,arid
  vcd_analyzer search sim.vcd --condition "changed(data_out),valid=0" --show data_out,valid
  vcd_analyzer search sim.vcd --condition "ch0_valid=1,ch0_ready=1" --condition "ch1_valid=1,ch1_ready=1"
  vcd_analyzer search sim.vcd --condition "valid=x"
  vcd_analyzer --json summary sim.vcd --filter tvalid,tready

Notes:
  search requires at least one observed value_change in the VCD data section;
  empty waveforms are reported as an input/data issue rather than as a false
  "no match" result.

  Search time windows: with no --end, the effective end is the file's last timestamp.
  With an explicit --end beyond the last timestamp, the last known state is
  extended into that window (the same last-known-value persistence used by
  snapshot/compare); a --begin past the last timestamp without --end is an
  error, while with --end it simply queries the extended window.

  Value-change fidelity: multiple value changes to a signal within one
  timestamp (legal per IEEE 1364-2005, e.g. delta-cycle style writers) are all
  emitted, in order. A record that merely re-asserts a signal's current value
  -- a consecutive duplicate, or a $dumpall/$dumpon checkpoint re-emitting the
  current value -- is a no-op and adds no change event. search's event mode
  reports one event per qualifying transition record on the same basis; a
  clause requiring SEVERAL signals to transition together reports the tick once,
  since coincidence is a property of the tick rather than of any one record.
"""

__version__ = '1.5.6'

import sys
import os
import re
import math
import json
import argparse
import tempfile
from array import array
import bisect
import mmap
import struct
import time
from collections import defaultdict
from fractions import Fraction
from functools import lru_cache

