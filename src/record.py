import idaapi

idaapi.require('visitors.unordered')
idaapi.require('inter_procedural')
idaapi.require('libs.utils')
idaapi.require('models.gfactory')

from libs.utils import encode_summary, decode_summary, get_summary, rule
from inter_procedural import CallGraphGenerator, CallGraph
from models.gfactory import *
from py2neo.matching import \
    NodeMatcher, RelationshipMatcher, \
    EQ, NE, LT, LE, GT, GE, \
    STARTS_WITH, ENDS_WITH, CONTAINS, LIKE, \
    IN, AND, OR, XOR

def make_loc(binary, fname, blk, idx):
    tmp = '_'.join([str(blk), str(idx)])
    return '$'.join([binary, fname, tmp])


class Recorder:
    def __init__(self) -> None:
        self.graph, self.repo = connect()
        self.summary = rule('summary')
        self.curr_cgg = None
        self.curr_callgraph = None
    
    def update_db(self, binary):
        self.graph, self.repo = connect(binary)

    '''
    Helper function: transfer
    To transfer from base model to submodel
    '''
    def transfer(self, obj):
        if isinstance(obj, Statement):
            model = cate2model[obj.cate]
            primary_value = obj.__primaryvalue__
        if isinstance(obj, Node):
            model = cate2model[obj.get('cate')]
            primary_value = obj.get('location')
        
        return self.repo.get(model, primary_value)
    
    '''
    Helper function: get_invoke
    To get the callback func of the blocl
    '''
    def get_invoke(self, blk):
        fname = None
        for r in self.graph.match((blk,None),r_type='CONTAIN').all():
            if r.end_node.get('vid').endswith('_16'):
                invoke_field = r.end_node
                for ar in self.graph.match((None,invoke_field),r_type='ASSIGN_TO').all():
                    assign = ar.start_node
                    gl = self.graph.match((assign,None),r_type='ASSIGN_FROM').first().end_node
                    if gl.has_label('gGlobalLiteral'):
                        if gl.get('name') and gl.get('name').startswith('sub_'):
                            fname = gl.get('name')
                            break
                break
        
        return fname

    def refactor_stkblk(self, fname):
        stkblks = []
        for stkblk in self.repo.match(gStkBlk).where(layout=STARTS_WITH(fname)).all():
            stkblks.append((stkblk.__node__.identity, stkblk))
        stkblk_map = dict(stkblks)
        to_update = []
        to_update.extend(list(stkblk_map.values()))

        # Build RelateTo relationship from stkblk to memobj
        for memobj in self.repo.match(gMemObj).where(vid=STARTS_WITH(fname)).all():
            base = list(memobj.base.triples())[0][2]
            if base.__primaryvalue__ in stkblk_map:
                stkblk = stkblk_map.get(base.__primaryvalue__)
                stkblk.lvars.add(memobj)

        # Remove duplication of localvars which equal to existing memobj
        for stkblk in stkblk_map.values():
            if not list(stkblk.lvars.triples()): 
                continue
            op = list(stkblk.lvars.triples())[0][2]
            node = self.graph.nodes.get(op.__node__.identity)
            base_vid = node.get('vid').rsplit('_', 1)[0]

            lv_nodes = self.graph.nodes.match('gLocalVar').where(vid=STARTS_WITH(f"{base_vid}_")).all()
            memobj_map = dict([(memobj.vid, memobj) for memobj in \
                self.repo.match(gMemObj).where(vid=STARTS_WITH(f"{base_vid}_")).all()])

            for lv_node in lv_nodes:
                memobj = memobj_map[lv_node.get('vid')]
                rs = self.graph.match((None,lv_node), r_type="USE").all()
                for r in rs: #TODO:call or msg
                    call = self.repo.match(gCall, r.start_node.get('location')).first()
                    call.args.add(memobj, argidx=r.get('argidx'))
                    self.graph.separate(r)
                    to_update.append(call)
            for lv_node in lv_nodes: 
                self.graph.delete(lv_node)

        # Guide the memobj from localvars, which point to the stkblk, to the stkblk itself
        for stkblk in stkblk_map.values():
            alias_nodes = [r.start_node for r in self.graph.match((None, stkblk.__node__), r_type="POINT_TO").all()]
            for alias_node in alias_nodes:
                rs = self.graph.match((None, alias_node), r_type="REFER_TO").all()
                for r in rs:
                    memobj = self.repo.get(gMemObj, r.start_node.get('vid'))
                    self.graph.separate(r)
                    memobj.base.add(stkblk)
                    stkblk.lvars.add(memobj)
                    to_update.append(memobj)
        
        for stkblk in to_update:
            self.repo.save(stkblk)

    def refactor_jump(self, fname):
        for jmp in self.repo.match(Statement).where("_.cate ='Jump'", location=STARTS_WITH(fname)).all():
            jmp = self.transfer(jmp)
            curr_blk = jmp.location.rsplit('_', 1)[0]
            loc = '_'.join([str(jmp.dest), '0'])
            floc = '$'.join([fname, loc])
            tar = self.repo.get(Statement, floc)
            jmp.succs.add(tar)
            for name in jmp.func_dep:
                op = self.repo.match(Statement).where(f"_.name = '{name}'", \
                    location=STARTS_WITH(f'{curr_blk}_')).all()[-1]
                ret = self.repo.get(gRet, op.location)
                jmp.conditions.add(ret)
            if jmp.is_goto:
                next_blk = '$'.join([curr_blk.split('$')[0] , str(int(curr_blk.split('$')[-1])+1)])
                fake_succ = self.repo.match(Statement).where(f"_.location = '{next_blk}_0'").first()
                jmp.succs.remove(fake_succ)
            self.repo.save(jmp)
    
    def complete(self):
        # Complete relations not convenient to add by gFactory
        refers = self.graph.match(None, r_type="REFER_TO").all()
        for r in refers:
            if not self.graph.match((r.end_node, r.start_node), r_type="CONTAIN").all():
                self.graph.merge(CONTAIN(r.end_node, r.start_node))

    def commit_func(self, proc_graph, fname, binary):
        func = self.build_func(proc_graph, fname, binary)
        self.graph.push(func)
        
        self.refactor_stkblk(fname)
        self.refactor_jump(fname)
        self.complete()

    def build_func(self, proc_graph, fname, binary):
        func = Func()
        func.name = fname
        func.binary = binary
        func.argidx_size = proc_graph.mba.argidx.size()
        func.retvaridx = proc_graph.mba.retvaridx
        func.entry_ea = proc_graph.mba.entry_ea

        prev = func
        nodes = proc_graph.node_set
        for blk in nodes:
            if not nodes[blk]: continue
            next = self.build_each_blk(nodes[blk], binary, fname, blk)
            if not next: continue
            if isinstance(prev, Func):
                prev.start.add(next)
            elif isinstance(prev, Statement):
                while list(prev.succs.triples()):
                    prev = list(prev.succs.triples())[0][2]
                prev.succs.add(next)
            prev = next
        
        if not isinstance(prev, Func):
            while list(prev.succs.triples()):
                prev = list(prev.succs.triples())[0][2]

            bfloc = make_loc(binary, fname, len(nodes), 0)
            end = gFactory.make_statement(None, bfloc)
            prev.succs.add(end)

        return func

    def build_each_blk(self, nodes, binary, fname, blk):
        stns = []
        for node in nodes:
            bfloc = make_loc(binary, fname, blk, len(stns))
            stn = gFactory.make_statement(node, bfloc)
            if stn and isinstance(node, vu.Assign) and \
                (isinstance(node.source, vu.Call) or isinstance(node.source, vu.Msg)):
                stn.source.add(list(stns[-1].ret.triples())[0][2])
            if stn: stns.append(stn)
        
        for i in range(len(stns)):
            if i: 
                stns[i].preds.add(stns[i-1])
            if i < len(stns) - 1:
                stns[i].succs.add(stns[i+1])
        if stns: 
            return stns[0]

    '''
    Transfer the relations from the duplication to the original object
    '''
    def migrate(self, dup_n, ori_m):
        to_update = []

        for r in self.graph.match((None, dup_n),None):
            # Deal with the relation between statements and dup_memobj
            if r.start_node.has_label('Statement'):
                stm = self.transfer(r.start_node)

                rname = r.__repr__().split('(',1)[0]
                if rname == 'USE':
                    stm.args.add(ori_m, argidx=r.get('argidx'))
                elif rname == 'ASSIGN_FROM':
                    stm.source.add(ori_m)
                elif rname == 'ASSIGN_TO':
                    stm.dest.add(ori_m)
                elif rname == 'RECEIVER':
                    stm.recv.add(ori_m)
                elif rname == 'DEP_ON':
                    stm.conditions.add(ori_m)
                else: 
                    print(f"TODO: Unsolved stm: {ori_m}\n{dup_n}-{stm}:{rname}")

                self.graph.separate(r)
                to_update.append(stm)

            # Deal with the relation between dup_memobj and based dup_memobj
            elif r.start_node.has_label('gMemObj'):
                obj = self.repo.get(gMemObj, r.start_node.get('vid'))
                obj.base.add(ori_m)
                self.graph.separate(r)
                to_update.append(obj)

        return to_update

    '''
    Combine the context between the caller and the callee [within binary]
    '''
    def combine_context(self, binary):
        to_update = []
        native_layout = []
        # Identify the native stackblock and store the layout
        for stkblk in self.graph.nodes.match('gStkBlk').where(binary=binary).all():
            is_native = False
            handlers = [r.start_node for r in self.graph.match((None, stkblk), "POINT_TO").all()] 
            if handlers: 
                is_native = True
            for handler in handlers:
                if handler.get('vid').split('$')[-1] == '0':
                    is_native = False
            if is_native:
                native_layout.append(stkblk.get('layout'))

        # Combine each pair of stackblock with same layout
        for flayout in native_layout:
            layout = flayout.split('$')[-1]
            ori = self.repo.match(gStkBlk).where(layout=AND(ENDS_WITH(layout), EQ(flayout))).first()
            dup = self.repo.match(gStkBlk).where(layout=AND(ENDS_WITH(layout), NE(flayout))).first()
            ori_m_nodes = [self.graph.nodes.get(op.__node__.identity) for op in ori.lvars]
            ori_m_map = dict([(node.get('vid').rsplit('_')[-1], \
                self.repo.match(gMemObj, node.get('vid')).first()) for node in ori_m_nodes])

            if not (ori and dup):
                print(f"TODO: Unsolved block: {ori}{dup}")
                continue
            print(f"COMBINE {layout}:\nori:{ori}\ndup:{dup}")

            # Re-connect the localvar to the orignal stkblk
            for r in self.graph.match((None, dup.__node__), r_type="POINT_TO").all():
                lv_m = self.repo.get(gLocalVar, r.start_node.get('vid'))
                self.graph.separate(r)
                lv_m.alias.add(ori)
                to_update.append(lv_m)

            for op in dup.lvars:
                dup_n = self.graph.nodes.get(op.__node__.identity)
                dup_m = self.repo.match(gMemObj, dup_n.get('vid')).first()
                off = dup_m.vid.rsplit('_')[-1]
                ori_m = ori_m_map.get(off)
                if not ori_m: continue

                to_update.extend(self.migrate(dup_n, ori_m))

                self.graph.delete(dup_n)

            self.graph.delete(dup)
        
        for obj in to_update:
            self.repo.save(obj)
    
    '''
    Infer the alias of struct field and combine them together [within binary]
    '''
    def combine_alias(self, binary):
        to_update = []

        assigns = [self.transfer(stm) for stm in self.repo.match(Statement)\
            .where(cate='Assignment', binary=binary).all()]
        for assign in assigns:
            src, dst = None, None
            if list(assign.source.triples()):
                src = list(assign.source.triples())[0][2]
            if list(assign.dest.triples()):
                dst = list(assign.dest.triples())[0][2]
            if not(src and dst): continue   

            if src.__node__.has_label('gMemObj') and dst.__node__.has_label('gLocalVar'):
                refs2src = self.graph.match((None, src.__node__), 'REFER_TO').all()
                refs2dst = self.graph.match((None, dst.__node__), 'REFER_TO').all()
                refs2src_map = dict([(r.start_node.get('vid').rsplit('_',1)[-1], r) for r in refs2src])
                refs2dst_map = dict([(r.start_node.get('vid').rsplit('_',1)[-1], r) for r in refs2dst])
                joint = set(refs2src_map.keys()) & set(refs2dst_map.keys())
                
                if joint:
                    dst_m = self.repo.get(gLocalVar, dst.__node__.get('vid'))
                    src_m = self.repo.get(gMemObj, src.__node__.get('vid'))
                    dst_m.alias.add(src_m)
                    to_update.append(dst_m)

                    for off in joint:
                        dup_n = refs2dst_map[off].start_node
                        ori_m = self.repo.get(gMemObj, refs2src_map[off].start_node.get('vid'))
                        to_update.extend(self.migrate(dup_n, ori_m))
                        self.graph.delete(dup_n)
        
        for obj in to_update:
            self.repo.save(obj)

    def add_callback(self, binary):
        for blk in self.graph.nodes.match('gStkBlk', binary=binary).all():
            fname = self.get_invoke(blk)
            if not fname: continue

            for old in ['+','-',' ',':','[',']']:
                fname = fname.replace(old,'_')
            
            func = self.graph.nodes.match('Function', name=fname).first()
            callsites = []
            pts = self.graph.match((None,blk),r_type='POINT_TO').all()

            for pt in pts:
                handler = pt.start_node
                callsites.extend([r.start_node for r in self.graph.match((None,handler),r_type='USE').all()])

            for callsite in callsites:
                self.graph.merge(CALLBACK(callsite, func))

    '''
    Summary-based dataflow within cgg of each binary
    '''
    def process_dataflow(self, cg:CallGraph):
        self.curr_callgraph = cg
        for entry in cg.entry_points:
            if entry in self.summary: continue
            stack = [entry]
            self.dfs_dataflow_dispatcher(entry, stack)

    def dfs_dataflow_dispatcher(self, fname, stack):
        print(f"Meet {fname}")
        callbacks = set()
        caller = self.curr_callgraph.procedure_map.get(fname)
        if not caller: return
        for callee_name in caller['callees']:
            callee = self.curr_callgraph.procedure_map.get(callee_name)
            if not callee: continue
            if callee['is_callback']: 
                callbacks.add(callee_name)
                continue
            if callee_name not in self.summary:
                if callee_name not in stack:
                    stack.append(callee_name)
                    self.dfs_dataflow_dispatcher(callee_name, stack)
                else:
                    continue
        self.summary[fname] = self.intraprocedural_dataflow(fname)
        for callback in callbacks:
            if callee_name not in stack:
                stack.append(callee_name)
                self.dfs_dataflow_dispatcher(callback,stack)
            else:
                continue

    def intraprocedural_dataflow(self, fname):
        print(f"Process on {fname}")
        for stm in self.repo.match(Statement).where(location=STARTS_WITH(fname)).all():
            if stm.cate == 'Assignment':
                assign = self.transfer(stm)
                src, dst = None, None
                if list(assign.source.triples()):
                    src = list(assign.source.triples())[0][2]
                if list(assign.dest.triples()):
                    dst = list(assign.dest.triples())[0][2]
                if not(src and dst): continue
                self.graph.merge(DATA_DEP(dst.__node__, src.__node__))
            elif stm.cate == 'Arithmetic':
                pass
            elif stm.cate == 'MsgSend':
                msg = self.transfer(stm)
                ret = self.load_func_summary(msg)
                if not ret:
                    if list(msg.recv.triples()):
                        recv = self.graph.nodes.get(list(msg.recv.triples())[0][2].__node__.identity)
                    else: recv = None
                    ret = list(msg.ret.triples())[0][2]
                    args = [self.graph.nodes.get(op.__node__.identity) for op in msg.args]
                    for arg in args:
                        self.graph.merge(DATA_DEP(ret.__node__, arg))
                    if recv:
                        self.graph.merge(DATA_DEP(ret.__node__, recv))
            elif stm.cate == 'Call':
                call = self.transfer(stm)
                ret = list(call.ret.triples())[0][2]
                args = [self.graph.nodes.get(op.__node__.identity) for op in call.args]
                for arg in args:
                    self.graph.merge(DATA_DEP(ret.__node__, arg))
            elif stm.cate == 'Jump':
                jmp = self.transfer(stm)
                for cond in jmp.conditions:
                    pass
        
        return self.gen_summary(fname)

    # Support msgsend and block invoke
    def gen_summary(self, fname):
        func = self.repo.get(Func, fname)
        if not func:
            return None
        effect = {0:[], 1:[]}
        if not(func.argidx_size) or not(func.retvaridx):
            return None
        # Need to exclude the rsi which is the sel string
        self_vid = f"{fname}$0"
        arg_vids = [f"{fname}${str(i)}" for i in range(func.argidx_size) if i > 1]
        for i in range(func.argidx_size):
            if i <= 1: continue
            effect[i] = []

        if func.retvaridx > -1:
            ret_vid = f"{fname}${func.retvaridx}"
            # Test the relation between self and ret
            cypher = f"MATCH p=(a:gLocalVar)-[:DATA_DEP|CONTAIN*]->(b:gLocalVar) \
                where a.vid='{ret_vid}' AND b.vid='{self_vid}' RETURN p"
            p = self.graph.run(cypher).to_subgraph()
            if p:
                effect[0].append(1)

            # Test the relation between other args and ret
            for arg_vid in arg_vids:
                cypher = f"MATCH p=(a:gLocalVar)-[:DATA_DEP|CONTAIN*]->(b:gLocalVar) \
                    where a.vid='{ret_vid}' AND b.vid='{arg_vid}' RETURN p"
                p = self.graph.run(cypher).to_subgraph()
                if p:
                    effect[0].append(int(arg_vid.split('$')[-1]))

        summary = encode_summary(effect)
        print(f"{fname}: {summary}, {effect}")

        return summary

    def load_func_summary(self, stm):
        if isinstance(stm, gMsg):
            ret = list(stm.ret.triples())[0][2]
            if list(stm.recv.triples()):
                recv = self.graph.nodes.get(list(stm.recv.triples())[0][2].__node__.identity)
            else: recv = None
            items = [(0, ret.__node__), (1, recv)]
            items.extend([(triple[1][1].get('argidx')+2, self.graph.nodes.get(triple[2].__node__.identity)) \
                for triple in stm.args.triples()])
            func_map = dict(items)
            if stm.name and get_summary(self.summary, stm.name):
                summary =  get_summary(self.summary, stm.name)
                effect = decode_summary(summary)
                for dst, srcs in effect.items():
                    dst_node = func_map.get(dst)
                    for src in srcs:
                        src_node = func_map.get(src)
                        if dst_node and src_node:
                            self.graph.merge(DATA_DEP(dst_node, src_node))
                return 1
            else:
                print(f"No summary: {stm.name}")

        elif isinstance(stm, gCall):
            pass
            
        return 0

    '''
    Build COME_FROM relation between callers and callees
    '''
    def connect_procedurals(self, binary):
        for r in self.graph.match(None, r_type="START").all():
            callee = r.start_node
            if not(callee.get('binary') == binary):
                continue
            fname = callee.get('name')
            call_to_set = self.graph.match((None, callee), r_type="CALL_TO").all()
            for call_to in call_to_set:
                callsite = call_to.start_node
                uses = self.graph.match((callsite,None), r_type="USE").all()
                for use in uses:
                    caller_arg = use.end_node
                    arg_vid = f"{fname}${str(use.get('argidx')+2)}"
                    callee_arg = self.graph.nodes.match("gLocalVar", vid=arg_vid).first()
                    if callee_arg:
                        self.graph.merge(COME_FROM(callee_arg, caller_arg))