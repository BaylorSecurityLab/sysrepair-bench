# meta4/ad-vm/lab/attacker/impacket_logfix.py
#
# Repairs impacket's logging under this Kali build. Installed via
# zz-impacket-logfix.pth, which Python executes at interpreter startup, so this
# applies to every impacket entry point without wrapping any of them.
#
# NOT installed as sitecustomize.py: Debian ships
# /usr/lib/python3.13/sitecustomize.py, the stdlib path precedes dist-packages,
# and a second sitecustomize there is simply never imported. That failure is
# invisible -- `'sitecustomize' in sys.modules` is still True, because the
# DEBIAN one loaded -- so it reads as a working fix until you check whether the
# factory actually changed. A .pth is the supported hook for this.
#
# THE PROBLEM
#
# impacket 0.14.0.dev0 formats log records with a '%(identity)s' field so that
# multi-target runs can label which host a line belongs to. Several tools --
# printerbug.py, shipped as impacket-spoolsample -- log through a plain logger
# that never sets that attribute. Formatting then raises:
#
#   ValueError: Formatting field not found in record: 'identity'
#
# Python catches formatter errors per record, prints "--- Logging error ---"
# plus a traceback to stderr, and DISCARDS THE MESSAGE. The process still exits
# 0.
#
# WHY IT MATTERED
#
# Every diagnostic line the tool emits is destroyed -- "Bind OK", the coercion
# attempt, the returned error code. scenario-16 greps that output to decide
# whether MS-RPRN coercion was accepted or refused, so with the logger broken
# it could observe NOTHING and fell through to "patch / mitigation NOT in
# place". The scenario was ungradeable no matter how it was invoked.
#
# The image's tool gate had explicitly waved this through as "a cosmetic
# logging-format traceback ... while remaining functional", on the grounds that
# usage text still appeared. Usage text comes from argparse, which does not go
# through logging -- so the one output that survived was the one that proved
# nothing. A tool whose logging is destroyed is not functional for a check that
# reads its logs.
#
# THE FIX
#
# Give every LogRecord an 'identity' attribute if it lacks one. An empty
# default is the correct value for single-target runs, which is what the
# scenarios do; tools that DO set identity are unaffected because the factory
# only fills in what is missing.

import logging

_previous_factory = logging.getLogRecordFactory()


def _record_factory(*args, **kwargs):
    record = _previous_factory(*args, **kwargs)
    if not hasattr(record, "identity"):
        record.identity = ""
    return record


logging.setLogRecordFactory(_record_factory)
