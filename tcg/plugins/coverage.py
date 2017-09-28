#!/usr/bin/env python

import os, sys, operator, tcg_plugin_python

symbols = set([])

pc_count = {}

def on_block_exec(address, size, symbol=None):
    if symbol: symbols.add(symbol)

def on_instr_exec(address):
    pc_count[address] = pc_count.get(address, 0) + 1

def on_progr_end():
    for symbol in sorted(symbols, key=operator.attrgetter('address')):
        print symbol.address, symbol.name, symbol.size
        for instr in tcg_plugin_python.get_disas_code(symbol.address, symbol.size):
            count = pc_count.get(instr.address, 0)
            print '  %s%d 0x%x:%s %s %s' % (
                count and '\033[1;32m' or '\033[1;30m',
                count, instr.address, '\033[1;37m', instr.mnemonic, instr.op_str)

