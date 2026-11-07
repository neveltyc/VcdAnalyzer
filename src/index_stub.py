# ================================================================
# Part 4: Index sidecar — full variant only (this is the lite build)
# ================================================================
#
# vcd_analyzer_lite.py is the pure-Python build with 1.5.6 behavior:
# no index sidecars are read, built or refreshed here. The Part-4 slot is
# occupied by this stub so the rest of the file (commands, CLI) assembles
# unchanged against either variant. Anything index-related a user tries
# gets ONE clear answer — this is the lite build, the feature ships in the
# full vcd_analyzer.py — instead of a silently slower emulation: silent
# divergence between variants is the one thing this design never does.

_FAST_ONLY = ('the index sidecar ships in the full vcd_analyzer.py only — '
              'this is the lite (pure Python) build; see the project releases page')


def sidecar_path(vcd_path):
    return str(vcd_path) + '.vcidx'


def _variant_env_notice():
    """Lite build: surface misdirected full-version options for every
    command (full variant: same-name no-op — nothing to warn about)."""
    for var in ('VCD_ANALYZER_AUTO_INDEX', 'VCD_ANALYZER_INDEX_THREADS'):
        if os.environ.get(var):
            _warn('{} is a full-version option and is ignored by this '
                  'lite build'.format(var), cat='index_full_only_' + var)


def try_index(vcd_path):
    """No index in the lite build."""
    return None


def maybe_auto_build(parser, vcd_path):
    """Never builds in the lite build."""
    return None


def cmd_index(vcd, args):
    """Every `index` invocation — explicit, --force, --output or the hidden
    --auto — gets the same pointer to the full build."""
    sys.exit('Error: ' + _FAST_ONLY)
