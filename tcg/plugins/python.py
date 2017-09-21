#!/usr/bin/env python
#
# TCG plugin for QEMU: python plugin for QEMU
#
# Copyright (C) 2017 STMicroelectronics
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import os, sys

import qemu

try:
    import capstone
except ImportError as e:
    print >>sys.stderr, 'error: ' + e.message
    sys.exit(1)

try:
    assert 0x02070000 <= sys.hexversion < 0x03000000
except:
    print >>sys.stderr, 'error: python-2.7 only!'
    sys.exit(1)


# ############################################################################


def on_progr_start(uname=None):
    global md
    assert uname == 'x86_64', 'unsupported target!'
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)


def on_progr_end():
    print 'end'


def on_block_trans(pc, size, sym_id=None, sym_pc=None, sym_size=None):
    print >>sys.stderr, 'TRNS', hex(pc), size, sym_id, sym_pc, sym_size


def on_block_exec(pc, size):
    print >>sys.stderr, 'EXEC', hex(pc), size
    for (address, size, mnemonic, op_str) in md.disasm_lite(qemu.getcode(pc, size), pc):
       print '0x%x: %s %s' % (address, mnemonic, op_str)


# ############################################################################
