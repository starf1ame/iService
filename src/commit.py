import idaapi
import time
import os
import pickle
from pathlib import Path
import sys
sys.setrecursionlimit(0x100000)

idaapi.require("record")
idaapi.require('models.pg')

from record import *
from models.pg import Entry, Binary, Sop, get

rec = Recorder()
session, engine = get()
graph, repo = connect()


def setup_env():
    global path, binary, pkls, pkls_bin
    ph = 'os'
    env = idaapi.get_input_file_path().rsplit(f'/{ph}/')[0]
    path = idaapi.get_input_file_path().rsplit(f'/{ph}/')[-1]
    binary = path.rsplit('/')[-1]

    pkls = os.path.join(env,'pkls')
    pkls_bin = os.path.join(pkls, binary)


def commit_service():
    isNeed = False
    global graph, repo, rec
    cg = load_service()
    if not cg: return 0
    for fname in cg.procedure_map:
        proc = cg.procedure_map.get(fname)
        pkl_name = f"{hex(proc.get('ea'))}.pkl"
        f_pkl = os.path.join(pkls_bin, pkl_name)
        print(fname, f_pkl)
        if os.path.exists(f_pkl):
            if not isNeed:
                dbs = graph.run("SHOW DATABASES").to_series()
                if not binary in dbs.values:
                    graph.run(f"CREATE DATABASE {binary}")
                graph, repo = connect(binary)
                rec.update_db(binary)
                isNeed = True
                print("Start commiting functions...")
            with open(f_pkl, 'rb') as f:
                func = pickle.load(f)
                graph.push(func)
                rec.refactor_stkblk(fname)
                rec.refactor_jump(fname)
        else:
            print(f"[x]Failed to load {fname}")
    if not isNeed:
        return 0
    rec.complete()
    print("Start dataflow analysis...")
    rec.combine_context(binary)
    rec.combine_alias(binary)
    rec.add_callback(binary)
    rec.process_dataflow(cg)
    rec.connect_procedurals(binary)
    return 1


def load_service():
    cg = None
    cg_pkl = os.path.join(pkls_bin, 'callgraph.pkl')
    if os.path.exists(cg_pkl):
        with open(cg_pkl, 'rb') as f:
            cg = pickle.load(f)
    return cg


def commit_framework():
    global graph, repo, rec
    entries = session.query(Entry).filter_by(caller=path).all()
    fw_paths = set([entry.binary_path for entry in entries])
    for fw_path in fw_paths:
        fw = fw_path.rsplit('/')[-1]
        cg, funcs = load_framework(fw)
        if not cg:
            print(f"[x]Failed to load {fw_path}")
            continue
        print(f"Start commiting framework {fw}...")
        for func in funcs:
            fname = func.name
            graph.push(func)
            rec.refactor_stkblk(fname)
            rec.refactor_jump(fname)
        rec.complete()
        rec.combine_context(fw)
        rec.combine_alias(fw)
        rec.add_callback(fw)
        rec.process_dataflow(cg)
        rec.connect_procedurals(fw)


def load_framework(framework):
    cg, funcs = None, []
    pkls_fw = os.path.join(pkls, framework)
    cg_pkl = os.path.join(pkls_fw, 'callgraph.pkl')
    if os.path.exists(cg_pkl):
        with open(cg_pkl, 'rb') as f:
            cg = pickle.load(f)
    if not cg: return None, []
    for fname in cg.procedure_map:
        proc = cg.procedure_map.get(fname)
        pkl_name = f"{hex(proc.get('ea'))}.pkl"
        f_pkl = os.path.join(pkls_fw, pkl_name)
        if os.path.exists(f_pkl):
            with open(f_pkl, 'rb') as f:
                func = pickle.load(f)
                funcs.append(func)
    return cg, funcs


def make_graph():
    time_start=time.time()
    re = commit_service()
    if re:
        print("Finish commiting service")
    else:
        print("Nothing to commit")
        return
    commit_framework()
    time_end=time.time()
    print(f"[*] Time cost for build graph and dataflow: {time_end-time_start}")
    print("Start identifying sensitive operations...")
    identify_sop()
    print("All finished.")


def get_oc_sinks():
    sink_objc = rule('objc')
    sink_list = []
    for clazz, sels in sink_objc.items():
        for sel in sels.keys():
            name = f"{sel[0]}[{clazz} {sel[2:]}]"
            sink_list.append(name)

    return sink_list


def get_c_sinks():
    sink_list = []
    for rules in rule('c').values():
        sink_list.extend([f"_{f}" for f in rules.keys()])

    return sink_list


def identify_sop():
    global graph
    oc_list = get_oc_sinks()
    c_list = get_c_sinks()
    nodes = []
    for fname in oc_list:
        nodes.extend(graph.nodes.match("Statement", name=fname).all())
    for fname in c_list:
        nodes.extend(graph.nodes.match("Statement", name=fname).all())
    
    if not nodes:
        graph, _ = connect()
        graph.run(f"DROP DATABASE {binary}")
    else:
        for node in nodes:
            fname = node.get('name')
            loc = node.get('location')
            if fname[0] in ['+','-']:
                cate = 'oc'
            else:
                cate = 'c'
            if not(session.query(Sop).filter_by(loc=loc).all()):
                session.add(Sop(cate=cate, name=fname, loc=loc, service=path, binary=node.get('binary')))
        session.commit()


if __name__ == "__main__":
    idaapi.require('batch')
    from batch import BatchMode

    with BatchMode():
        setup_env()
        make_graph()