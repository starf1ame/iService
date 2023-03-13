import idaapi
import sys
sys.setrecursionlimit(0x100000)

idaapi.require('libs.hint')
idaapi.require("record")
idaapi.require('models.pg')

from record import *
from models.pg import Entry, InputValidation, PermissionBase, get
from libs.hint import authentications

from py2neo.data import walk


def setup_env():
    global path, binary, graph, session

    ph = 'os'
    env = idaapi.get_input_file_path().rsplit(f'/{ph}/')[0]
    path = idaapi.get_input_file_path().rsplit(f'/{ph}/')[-1]
    binary = path.rsplit('/')[-1]

    graph, repo = connect(binary)
    session, engine = get()


def get_auth():
    auth_base = {}
    for fname in authentications:
        auths = graph.nodes.match('Statement',name=CONTAINS(fname)).all()
        for auth in auths:
            ab = PermissionBase(service=path, location=auth.get('location'), fname=auth.get('name'))
            auth_base[auth.get('location')] = auth.get('name')
            if not(session.query(PermissionBase).filter_by(service=path, location=auth.get('location')).all()):
                session.add(ab)
                session.commit()
        gls = graph.nodes.match('gGlobalLiteral',name=CONTAINS(fname)).all()
        for gl in gls:
            rs = graph.match((None,gl), r_type='USE').all()
            for r in rs:
                stm = r.start_node
                if stm.get('location') in auth_base:
                    continue
                ab = PermissionBase(service=path, location=stm.get('location'), fname=fname)
                auth_base[stm.get('location')] = fname
                if not(session.query(PermissionBase).filter_by(service=path, location=stm.get('location')).all()):
                    session.add(ab)
                    session.commit()

    
    print(f"[*] Permission check base found: {auth_base.items()}")
    
    return auth_base


def get_ipc_inputs():
    ipc_inputs = []
    for entry in session.query(Entry).filter_by(binary_path=path).all():
        func = graph.nodes.match("Function", name=entry.fname).first()
        if not(func and entry.fname):
            continue
        size = func.get('argidx_size')
        if not size: 
            continue
        src = []
        if entry.fname.startswith('sub_'):
            for i in range(1,size):
                src.append('$'.join([entry.fname, str(i)]))
        else:
            for i in range(2,size):
                src.append('$'.join([entry.fname, str(i)]))
        ipc_inputs.extend(src)
    
    return ipc_inputs


def get_oc_sinks_map():
    sink_objc = rule('objc')
    sinks = {}
    for clazz, sels in sink_objc.items():
        for sel, args in sels.items():
            name = f"{sel[0]}[{clazz} {sel[2:]}]"
            sinks[name] = args

    return sinks


def get_c_sinks_map():
    sinks = {}
    for rules in rule('c').values():
        for fname, args in rules.items():
            sinks[f"_{fname}"] = args

    return sinks


def get_sensitive_para():
    global graph
    oc_map = get_oc_sinks_map()
    c_map = get_c_sinks_map()
    sink_map = {}
    sink_map.update(oc_map)
    sink_map.update(c_map)
    callsites = []
    for fname in sink_map.keys():
        callsites.extend(graph.nodes.match("Statement", name=fname).all())

    sinks = {}

    for callsite in callsites:
        graph.match((callsite, None), r_type='USE')
        args = sink_map.get(callsite.get('name'))
        for i in range(len(args)):
            if args[i]:
                r = graph.match((callsite, None), r_type='USE').where(argidx=i).first()
                if r and r.end_node.get('vid'):
                    para_id = '$'.join([callsite.get('name'), str(i)])
                    sinks[para_id] = r.end_node.get('vid')
    
    return sinks


def gen_slice(data_sg):
    def get_stm(op1, op2):
        s1=set([r.start_node for r in graph.match((None,op1),None).all()])
        s2=set([r.start_node for r in graph.match((None,op2),None).all()])
        stms = s1 & s2
        return list(stms)

    sg = list(walk(data_sg))
    flow = [item for item in sg if isinstance(item, DATA_DEP) or isinstance(item, COME_FROM)]
    flow.reverse()
    exec_path=[]

    for item in flow:
        if isinstance(item, DATA_DEP):
            stms = get_stm(item.start_node, item.end_node)
        if isinstance(item, COME_FROM):
            fname = item.start_node.get('func')
            nodes = [r.start_node for r in graph.match((None,item.end_node), None).all()]
            stms = [n for n in nodes if n.get('name')==fname]
            
        exec_path.append(stms[0])
    
    return exec_path


def get_reachable_path(ipc_inputs, sinks, cypher):
    dataflow = {}
    reachable = {}
    print('[*] Get reachable dataflow')
    for inn in ipc_inputs:
        for para, sink in sinks.items():
            cmd = cypher.replace('SOURCE', inn)
            cmd = cmd.replace('SINK', sink)
            p = graph.run(cmd)
            sg = p.to_subgraph()
            if sg:
                dataflow[para] = sg.nodes
                exec_slice = gen_slice(sg)
                reachable[para] = exec_slice
                print(f'Reachable dataflow: {inn}, {para}')
    
    return reachable


def get_condition_stms(reachable):
    jmps_map = {}

    for para, exec_slice in reachable.items():
        jmps_map[para] = []
        for i in range(len(exec_slice)-1):
            stm_1 = exec_slice[i]
            stm_2 = exec_slice[i+1]
            if not(stm_1.get('location') and stm_2.get('location')):
                continue
            cp = "MATCH (a:Statement {location:'SINK'}), (b:Statement {location:'SOURCE'}), path = shortestpath((a)-[:NEXT|CALL_TO|START|CALLBACK*]->(b)) RETURN path ORDER BY LENGTH(path) DESC LIMIT 1"
            cp = cp.replace('SOURCE', stm_2.get('location'))
            cp = cp.replace('SINK', stm_1.get('location'))
            p = graph.run(cp)
            sg = p.to_subgraph()
            if not sg:
                continue
            for stm in sg.nodes:
                if stm.get('cate') == 'Jump':
                    jmps_map[para].append(stm)
    return jmps_map


def get_input_validations(jmps_map, sinks):
    validations = []
    for para, jmps in jmps_map.items():
        for jmp in jmps:
            if jmp.get('func_dep'):
                for fname in jmp.get('func_dep'):
                    vid = sinks.get(para)
                    iv = InputValidation(para=para, vid=vid, service=binary, fname=fname, location=jmp.get('location'))
                    print(f'[*] Find input validation: {iv.para}, {iv.fname}')
                    validations.append(iv)
                    if not(session.query(InputValidation).filter_by(service=binary, para=para, location=jmp.get('location')).all()):
                        iv = InputValidation(para=para, vid=vid, service=binary, fname=fname, location=jmp.get('location'))
                        session.add(iv)
                        session.commit()
    return validations


def main():
    print('[*] Get ipc sources and sop sinks')
    ipc_inputs = get_ipc_inputs()
    sinks = get_sensitive_para()
    cypher ="MATCH (a:gLocalVar {vid:'SINK'}), (b:gLocalVar {vid:'SOURCE'}), path = shortestpath((a)-[:DATA_DEP|COME_FROM*]->(b)) RETURN path ORDER BY LENGTH(path) DESC LIMIT 1"

    reachable = get_reachable_path(ipc_inputs, sinks, cypher)

    jmps_map = get_condition_stms(reachable)

    print('[*] Get input validations')
    validations = get_input_validations(jmps_map, sinks)

    return validations


if __name__ == "__main__":
    idaapi.require('batch')
    from batch import BatchMode

    with BatchMode():
        setup_env()
        main()
        get_auth()