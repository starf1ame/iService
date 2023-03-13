import idaapi
import idc
import time
import os
import pickle
import sys
sys.setrecursionlimit(0x100000)

idaapi.require("record")
idaapi.require('models.pg')

from record import *
from models.pg import Entry, Binary, get


rec = Recorder()
session, engine = get()
graph, repo = connect()

def setup_env(mode):
    global path, binary, pkls_bin

    ph = 'os'
    env = idaapi.get_input_file_path().rsplit(f'/{ph}/')[0]
    path = idaapi.get_input_file_path().rsplit(f'/{ph}/')[-1]
    binary = path.rsplit('/')[-1]

    if not(session.query(Binary).filter_by(path=path).all()):
        session.add(Binary(path=path, cate=mode))
        session.commit()

    if '/cases/' in env:
        from pathlib import Path
        suffix = env.split('cases/')[-1]
        prefix = Path(__file__).parent.parent / 'cases'/ suffix
        pkls = os.path.join(prefix.__str__(),'pkls')
    else:
        pkls = os.path.join(env,'pkls')
    pkls_bin = os.path.join(pkls, binary)

    if not os.path.exists(pkls_bin):
        os.makedirs(pkls_bin)


def gen_callgraph(mode):
    if mode == 'service':
        cgg = CallGraphGenerator(binary=path, db=True)
    elif mode == 'framework':
        entries = [entry.fname for entry in session.query(Entry).filter(Entry.binary_path.endswith('/'+binary)).all()]
        cgg = CallGraphGenerator(entries=entries, binary=binary, db=True)
    cgg.build_call_relations()
    return cgg


def dump_callgraph(cg):
    pkl = os.path.join(pkls_bin, 'callgraph.pkl')
    print(f"instance: {type(cg), cg}")
    with open(pkl, 'wb') as fplk:
        pickle.dump(cg, fplk)


def dump_abstract(func):
    pkl = os.path.join(pkls_bin, hex(func.entry_ea)+'.pkl')
    print(f"instance: {type(func), func}")
    with open(pkl, 'wb') as fplk:
        pickle.dump(func, fplk)


def gen_abstract_graph(mode):
    print(f"[*] Mode is {mode}")
    print(f"[*] Slicing and generating call graph...")
    time_start=time.time()

    cgg = gen_callgraph(mode)
    cgg.dump_externals()

    time_end=time.time()
    print(f"[*] Time cost for idapython modules: {time_end-time_start}")

    dump_callgraph(cgg.dump_callgraph())

    print(f"[*] Abstracting functions before commiting...")
    time_start=time.time()

    for fname in cgg.procedure_map:
        print(f"Abstracting function: {fname}")
        extr = cgg.procedure_map[fname].graph
        func = rec.build_func(extr, fname, binary)
        dump_abstract(func)

    time_end=time.time()
    print(f"[*] Time cost for abstracting and dumping: {time_end-time_start}")
    
    return cgg # return cgg for debug


if __name__ == "__main__":
    idaapi.require('batch')
    from batch import BatchMode

    with BatchMode():
        mode = idc.ARGV[1]
        setup_env(mode)
        cgg = gen_abstract_graph(mode)