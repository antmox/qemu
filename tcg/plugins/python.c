/*
 * TCG plugin for QEMU: python plugin for QEMU
 *
 * Copyright (C) 2017 STMicroelectronics
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <unistd.h>
#include <libgen.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#ifdef CONFIG_PYTHON

#include <Python.h>

#include "tcg-plugin.h"
#include "disas/disas.h"
#include "target_syscall.h" // UNAME_MACHINE


#define DEBUG(fmt, ...)                                     \
    fprintf (stderr, "# DEBUG: " fmt "\n", ## __VA_ARGS__)


#define Py_DEBUG(msg, ...)                                  \
    Py_ExecStr("print '# DEBUG-PY:',\n" msg, ## __VA_ARGS__)


#define Py_ExecStr(stmt, ...)                               \
    do {                                                    \
        char *pystr;                                        \
        asprintf(&pystr, stmt, ## __VA_ARGS__);             \
        PyRun_SimpleString(pystr);                          \
        free(pystr);                                        \
    } while (0)


#define Py_CallRef(func, args)                              \
    do {                                                    \
        PyObject *pargs = args;                             \
        PyObject *pvalue =                                  \
            PyObject_CallObject(func, pargs);               \
        Py_DECREF(pargs);                                   \
        if (pvalue != NULL) {                               \
            Py_DECREF(pvalue);                              \
        } else {                                            \
            PyErr_Print();                                  \
            fprintf(stderr, "error: call failed!"           \
                    " stopping qemu!!!\n");                 \
            exit(1);                                        \
        } } while (0)


static struct {
    PyObject *pModule;
    PyObject *on_progr_start;
    PyObject *on_block_trans;
    PyObject *on_block_exec;
    PyObject *on_instr_exec;
    PyObject *on_progr_end;
} plugin_state = { 0 };


//
static PyObject *qemu_getcode(PyObject *self, PyObject *args)
{
    uint64_t address, size;
    if (!PyArg_ParseTuple(args, "ll", &address, &size))
        return NULL;
    return Py_BuildValue("s#", (char *)tpi_guest_ptr(0, address), size);
}


// qemu python module
static PyMethodDef qemu_methods[] = {
    {"getcode", qemu_getcode, METH_VARARGS, "Return code at given pc."},
    {NULL, NULL, 0, NULL}
};


// block translation
static void pre_tb_helper_data(
    const TCGPluginInterface *tpi, TPIHelperInfo info, uint64_t address,
    uint64_t *data1, uint64_t *data2, const TranslationBlock* tb)
{
    PyObject *pArgs, *pValue, *pFunc;

    pFunc = plugin_state.on_block_trans;

    if (pFunc == NULL) return;

    const char *symbol_id = NULL;
    const char *symbol_file = NULL;
    uint64_t symbol_address = 0;
    uint64_t symbol_size = 0;

    lookup_symbol4(address, &symbol_id, &symbol_file, &symbol_address, &symbol_size);

    pArgs = PyTuple_New(symbol_size ? 5 : 2);

    pValue = PyInt_FromLong(address);
    PyTuple_SetItem(pArgs, 0, pValue);

    pValue = PyInt_FromLong(tpi_tb_size(tb));
    PyTuple_SetItem(pArgs, 1, pValue);

    if (symbol_size) {
        pValue = PyString_FromString((const char *)(symbol_id));
        PyTuple_SetItem(pArgs, 2, pValue);

        pValue = PyInt_FromLong(symbol_address);
        PyTuple_SetItem(pArgs, 3, pValue);

        pValue = PyInt_FromLong(symbol_size);
        PyTuple_SetItem(pArgs, 4, pValue);
    }

    Py_CallRef(pFunc, pArgs);
}


// instr execution
static void after_exec_opc(uint64_t address)
{
    PyObject *pArgs, *pValue, *pFunc;

    pFunc = plugin_state.on_instr_exec;

    if (pFunc == NULL) return;

    pArgs = PyTuple_New(1);

    pValue = PyInt_FromLong(address);
    PyTuple_SetItem(pArgs, 0, pValue);

    Py_CallRef(pFunc, pArgs);
}


// instr translation
static void after_gen_opc(
    const TCGPluginInterface *tpi, const TPIOpCode *tpi_opcode)
{
    if (tpi_opcode->operator != INDEX_op_insn_start)
        return;

    // insert call to after_exec_opc
    TCGArg args[] = {
        GET_TCGV_I64(tcg_const_i64(tpi_opcode->pc)) };
    tcg_gen_callN(tpi->tcg_ctx, after_exec_opc, TCG_CALL_DUMMY_ARG, 1, args);
}


// block execution
static void pre_tb_helper_code(
    const TCGPluginInterface *tpi, TPIHelperInfo info, uint64_t address,
    uint64_t data1, uint64_t data2, const TranslationBlock* tb)
{
    PyObject *pArgs, *pValue, *pFunc;

    pFunc = plugin_state.on_block_exec;

    if (pFunc == NULL) return;

    pArgs = PyTuple_New(2);

    pValue = PyInt_FromLong(address);
    PyTuple_SetItem(pArgs, 0, pValue);

    pValue = PyInt_FromLong(tpi_tb_size(tb));
    PyTuple_SetItem(pArgs, 1, pValue);

    Py_CallRef(pFunc, pArgs);
}


// execution end
static void cpus_stopped(const TCGPluginInterface *tpi)
{
    PyObject *pFunc;

    pFunc = plugin_state.on_progr_end;
    if (pFunc != NULL) {
        Py_CallRef(pFunc, PyTuple_New(0));
    }

    pFunc = plugin_state.on_progr_start;
    if (pFunc != NULL)
        Py_XDECREF(pFunc);

    pFunc = plugin_state.on_block_trans;
    if (pFunc != NULL)
        Py_XDECREF(pFunc);

    pFunc = plugin_state.on_block_exec;
    if (pFunc != NULL)
        Py_XDECREF(pFunc);

    pFunc = plugin_state.on_instr_exec;
    if (pFunc != NULL)
        Py_XDECREF(pFunc);

    pFunc = plugin_state.on_progr_end;
    if (pFunc != NULL)
        Py_XDECREF(pFunc);

    if (plugin_state.pModule)
        Py_DECREF(plugin_state.pModule);

    Py_Finalize();
}


// execution start
void tpi_init(TCGPluginInterface* tpi)
{
    TPI_INIT_VERSION(tpi);
    TPI_DECL_FUNC_1(tpi, after_exec_opc, void, i64);

    tpi->cpus_stopped = cpus_stopped;
    tpi->pre_tb_helper_data  = pre_tb_helper_data;
    tpi->pre_tb_helper_code  = pre_tb_helper_code;
    tpi->after_gen_opc = after_gen_opc;

    char *plugin_dir = NULL, *plugin_base = NULL;
    assert(tpi->path_name);
    plugin_dir = dirname(strdup(tpi->path_name));
    plugin_base = (char *)"tcg_plugin_python";

    if (!plugin_base) {
        fprintf(stderr, "warning: invalid $PYTHON_PLUGIN! stopping plugin\n");
        return;
    }

    // starting python interpreter
    Py_Initialize();

    Py_InitModule("qemu", qemu_methods);

    PyList_Append(PySys_GetObject((char *)"path"), PyString_FromString(plugin_dir));

    {
        PyObject *pName, *pModule, *pFunc, *pArgs, *pValue;

        pName = PyString_FromString(plugin_base);
        assert(pName != NULL);

        pModule = PyImport_Import(pName);
        Py_DECREF(pName);

        if (pModule == NULL) {
            PyErr_Print();
            fprintf(stderr, "warning: failed to load \"%s\"! stopping plugin\n", plugin_base);
            return;
        }

        plugin_state.pModule = pModule;

        pFunc = PyObject_HasAttrString(pModule, "on_progr_start") ?
            PyObject_GetAttrString(pModule, "on_progr_start") : NULL;
        if (pFunc != NULL && PyCallable_Check(pFunc)) {
            plugin_state.on_progr_start = pFunc;
        }

        pFunc = PyObject_HasAttrString(pModule, "on_progr_end") ?
            PyObject_GetAttrString(pModule, "on_progr_end") : NULL;
        if (pFunc != NULL && PyCallable_Check(pFunc)) {
            plugin_state.on_progr_end = pFunc;
        }

        pFunc = PyObject_HasAttrString(pModule, "on_block_trans") ?
            PyObject_GetAttrString(pModule, "on_block_trans") : NULL;
        if (pFunc != NULL && PyCallable_Check(pFunc)) {
            plugin_state.on_block_trans = pFunc;
        }

        pFunc = PyObject_HasAttrString(pModule, "on_block_exec") ?
            PyObject_GetAttrString(pModule, "on_block_exec") : NULL;
        if (pFunc != NULL && PyCallable_Check(pFunc)) {
            plugin_state.on_block_exec = pFunc;
        }

        pFunc = PyObject_HasAttrString(pModule, "on_instr_exec") ?
            PyObject_GetAttrString(pModule, "on_instr_exec") : NULL;
        if (pFunc != NULL && PyCallable_Check(pFunc)) {
            plugin_state.on_instr_exec = pFunc;
        }

        pFunc = plugin_state.on_progr_start;
        if (pFunc != NULL) {
            pArgs = PyTuple_New(1);
            pValue = PyString_FromString(UNAME_MACHINE);
            PyTuple_SetItem(pArgs, 0, pValue);
            Py_CallRef(pFunc, pArgs);
        }
    }
}

#endif // CONFIG_PYTHON
