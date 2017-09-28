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

import os, sys, collections

try:
    import qemu, capstone
except ImportError as e:
    print >>sys.stderr, 'error: ' + e.message
    sys.exit(1)

try:
    from repoze.lru import lru_cache
except:
    print >>sys.stderr, 'warning: missing module repoze.lru!'
    def lru_cache(maxsize=None): return lambda f: f

try:
    assert 0x02070000 <= sys.hexversion < 0x03000000
except:
    print >>sys.stderr, 'error: python-2.7 only!'
    sys.exit(1)


# ############################################################################

plugins = []

capstone_md = None

block_sym = {}  # { address : symbol }

Symbol = collections.namedtuple('Symbol', ['name', 'address', 'size'])


# ############################################################################

@lru_cache(maxsize=None)
def get_disas_code(address, size):
    disas_code = capstone_md.disasm(qemu.getcode(address, size), address)
    return list(disas_code)

def get_symbol(address):
    return block_sym.get(address, None)

def plugins_callback(fct_name, *args):
    for plugin in plugins:
        try:
            fct = getattr(plugin, fct_name)
            fct(*args)
        except AttributeError: pass
        except: raise

def import_plugin(plugin_filename):
    # take basename and remove extension
    plugin_filename = os.path.realpath(plugin_filename)
    plugin_id = os.path.splitext(os.path.basename(plugin_filename))[0]
    # try already installed python plugins
    try:
        module = __import__('tcg_plugin_' + plugin_id, globals(), locals())
        return module
    except ImportError: pass
    except: raise
    # try plugin relative to current working dir
    if os.path.isfile(plugin_filename):
        sys.path.append(os.path.dirname(plugin_filename))
        module = __import__(plugin_id, globals(), locals())
        return module
    print >>sys.stderr, 'warning: plugin not found', plugin_id
    return None


# ############################################################################

def on_progr_start(uname=None):
    # import python plugins
    plugin_ids = os.getenv('PYTHON_PLUGIN', '').split(',')
    for plugin in plugin_ids:
        plugin_module = import_plugin(plugin)
        plugin_module and plugins.append(plugin_module)

    # initialize capstone module
    global capstone_md
    assert uname == 'x86_64', 'unsupported target!'
    capstone_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    # initialize python plugins
    plugins_callback('on_progr_start')

def on_progr_end():
    # finalize python plugins
    plugins_callback('on_progr_end')

def on_block_trans(address, size, sym_name=None, sym_address=None, sym_size=None):
    # update block_to_symbol map
    sym_name and block_sym.update([(address, Symbol(sym_name, sym_address, sym_size))])

def on_block_exec(address, size):
    # on_block_exec
    plugins_callback('on_block_exec', address, size, block_sym.get(address, None))

def on_instr_exec(address):
    # on_instr_exec
    plugins_callback('on_instr_exec', address)


# ############################################################################
