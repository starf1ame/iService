import idc
import idaapi
import idautils
import ida_bytes
import ida_name
import ida_segment
import ida_hexrays as hr

idaapi.require('libs.utils')
idaapi.require('libs.hint')
idaapi.require('visitors.unordered')
idaapi.require('visitors.simulation')

from libs.utils import genmc, rule, encode_summary, decode_summary, get_summary
import libs.hr
from visitors.simulation import SimVisitor
import visitors.unordered as vu
from collections import namedtuple

Sink = namedtuple('Sink',['clazz', 'selector', 'args'])

class GraphGenerator(SimVisitor):
    def __init__(self, mba):
        super().__init__(mba)
        self.node_set = {}
        self.curr_trace = '0'
        self.traces = set()
        if mba:
            self.gen_trace(0)
            
    def get_msgsend_name(self, node : vu.Msg)->str:
        name, tp, recv, sel = None, None, None, None
        if isinstance(node.receiver, vu.LocalVar):
            if node.tp: tp = node.tp
            elif node.receiver.idx in self.local_vars: tp = '+'
            else: tp = '-'
            if node.recv_type:
                recv = node.recv_type
            elif not self.local_types.get(node.receiver.idx) == 'id':
                recv = self.local_types.get(node.receiver.idx)
        elif isinstance(node.receiver, vu.MemObj):
            tp = '-'
            if node.recv_type:
                recv = node.recv_type
            else:
                recv = node.receiver.type
        elif isinstance(node.receiver, vu.CFString):
            tp = '-'
            recv = 'NSString'
        elif isinstance(node.receiver, vu.Clazz):
            recv, tp = node.receiver.name, '+'

        if isinstance(node.selector, vu.Selector):
            sel = node.selector.name
        elif isinstance(node.selector, vu.LocalVar):
            sel = self.local_vars.get(node.selector.idx)

        if not tp: tp = "*"
        if not recv: recv = "UNKNOWN"

        if not sel: sel = "UNKNOWN"
        else: node.sel_val = sel

        name = f"{tp}[{recv} {sel}]"
        node.name = name

        return name      

    def gen_trace(self, cur_block : int):
        dup_trace = self.curr_trace
        mblock = self.mba.get_mblock(cur_block)
        for i in range(mblock.succset.size()):
            self.curr_trace = dup_trace
            next_block = mblock.succ(i)
            self.curr_trace = self.curr_trace + ' ' + str(next_block)
            if self.curr_trace.split(' ').count(str(next_block)) > 1: 
                self.curr_trace = dup_trace
                continue
            self.gen_trace(next_block)
            
        if self.curr_trace.split(' ')[-1] == str(self.mba.qty - 1):
            self.traces.add(self.curr_trace)
    
    def visit(self):
        super().visit()
 
    def visit_block(self, mblock):
        self.node_set[self.cur_block] = []
        super().visit_block(mblock)

    def post_order_traversal(self, expr):
        left, right = None, None
        if isinstance(expr, vu.Assign):
            left = expr.source
            right = expr.dest

        elif isinstance(expr, vu.Jmp):
            if expr.jtp in libs.hr.m_jmp2:
                left = expr.cond[0]
                right = expr.cond[1]
                
        if isinstance(left, vu.Node):
            self.post_order_traversal(left)

        if isinstance(right, vu.Node):
            self.post_order_traversal(right)

        self.node_set[self.cur_block].append(expr)
        if isinstance(expr, vu.Msg):
            tp, val, dep = None, None, None
            tp = self.type_infer(expr)
            self.node_set[self.cur_block].append(vu.Factory.make_ret(tp, val, dep)) #TODO
    
    def visit_top_insn(self, insn):
        expr = super().visit_top_insn(insn)
        self.post_order_traversal(expr)

        return expr

    def visit_insn(self, insn):
        expr =  super().visit_insn(insn)
        return expr
    
    def visit_op(self, op):
        return super().visit_op(op)


class DataFlowExtractor(GraphGenerator):
    def __init__(self, mba, pre):
        super().__init__(mba)
        self.sources = set()
        if mba:
            for i in range(self.mba.argidx.size()):
                self.sources.add(list(self.mba.vars)[i].name)
        self.sink_map = {}
        self.transfers = {}
        self.preliminary = rule('summary')
        if pre:
            self.preliminary.update(pre)

    @property
    def readable_types(self):
        return {list(self.mba.vars)[k].name: str(v) for k, v in self.local_types.items()}
    
    @property
    def readable_vars(self):
        return {list(self.mba.vars)[k].name: str(v) for k, v in self.local_vars.items()}
    
    @property
    def trans(self):
        trans = {}
        for blk in self.transfers:
            curr = {}
            for vid, deps in self.transfers[blk].items():
                vname = list(self.mba.vars)[self.vid2idx(vid)].name
                ndeps = [list(self.mba.vars)[self.vid2idx(dep)].name for dep in deps]
                if not ndeps: continue
                if vname not in curr:
                    curr[vname] = set(ndeps)
                else:
                    curr[vname] |= set(ndeps)
            trans[blk] = curr
        
        return trans
    
    @staticmethod
    def vid2idx(vid):
        if not '_' in vid:
            return int(vid)
        else:
            return int(vid.split('_')[0])

    def get_vid(self, op):
        if isinstance(op, vu.MemObj):
            if isinstance(op.base, list):
                prefix = '&'+'&'.join([self.get_vid(v) for v in op.base])
            else:
                prefix = self.get_vid(op.base)
            if isinstance(op.off, list):
                suffix = '&'+'&'.join([self.get_vid(v) for v in op.off])
            else:
                suffix = str(op.off)
            if not prefix:
                return
            vid = '_'.join([prefix, suffix])
            op.vid = vid
        elif isinstance(op, vu.LocalVar):
            idx = op.idx
            off = op.raw.l.off
            if off:
                vid = '_'.join([str(idx), str(off)])
            else:
                vid = str(idx)
            op.vid = vid
        elif isinstance(op, vu.StackBlock):
            vid = str(op.idx)
        else:
            # print(f'WARNING: type {type(op)} is supported!')
            return

        return vid

    def gen_tar_blks(self):
        tar_blks = set()
        for sink in self.sink_map.keys():
            for blk, nodes in self.node_set.items():
                for node in nodes:
                    if isinstance(node, vu.Msg) and self.get_msgsend_name(node) == sink:
                        tar_blks.add(blk)
        return tar_blks

    def visit(self):
        super().visit()
        for i in range(1, self.mba.qty):
            self.transfers[i] = self.forward_in_block(i)

    # Used to print dataflow in a single block for human read
    def print_transfer(self, transfer : dict):
        for idx, idxs in transfer.items():
            vars = [list(self.mba.vars)[i].name for i in idxs]
            print(f"{list(self.mba.vars)[idx].name}({idx}) is effected by: {' '.join(vars)}") 

    # Used to generate dataflow in a single block
    def forward_in_block(self, block : int):
        transfer = {}
        nodes = self.node_set.get(block)

        def cared(op):
            if isinstance(op, vu.LocalVar) or \
                isinstance(op, vu.MemObj):
                return True

        def add_pair(dst, *srcs):
            dst_vid = self.get_vid(dst)
            if not dst_vid: return
            transfer[dst_vid] = []

            for src in srcs:
                src_vid = self.get_vid(src)
                if not src_vid: continue
                transfer[dst_vid].append(src_vid)

        for i in range(len(nodes)):
            node = nodes[i]
            if isinstance(node, vu.Assign):
                src, dest = node.source, node.dest
                if cared(src): 
                    self.get_vid(src)
                if cared(dest):
                    self.get_vid(dest)
                    if isinstance(src, vu.Msg):
                        transfer[self.get_vid(dest)] = []
                        ret_node = nodes[i-1]
                        transfer[self.get_vid(dest)].extend(ret_node.dep)
                    elif isinstance(src, vu.Call):
                        add_pair(dest, *src.args)
                    elif cared(src):
                        add_pair(dest, src)
            
            elif isinstance(node, vu.Arith) and cared(node.dest):
                left, right, dest = node.left, node.right, node.dest
                self.get_vid(left)
                self.get_vid(right)
                add_pair(dest, left, right)

            elif isinstance(node, vu.Load) and cared(node.dest):
                if node.memobj:
                    src = node.memobj
                else:
                    src = node.base
                dest = node.dest
                add_pair(dest, src)

            elif isinstance(node, vu.Msg):
                # Record the vid of the recv each arg
                self.get_vid(node.receiver)
                for arg in node.args:
                    self.get_vid(arg)

                name = self.get_msgsend_name(node)
                if not name:
                    continue
                if ':' not in name:
                    continue
                # Depend on predefined or pre-generated pattern
                summary = get_summary(self.preliminary, name)
                if summary:
                    effect = decode_summary(summary)
                    # print(f"summary is {summary}")
                    mapping = {} # map the idx of arglist to the var of current context
                    for idx in effect.keys():
                        # Receiver TODO: which fields?
                        if idx == 1 and isinstance(node.receiver, vu.LocalVar):
                            mapping[idx] = node.receiver
                        # Arguments
                        if idx > 1 and len(node.args)>idx:
                            if isinstance(node.args[idx-2], vu.LocalVar):
                                mapping[idx] = node.args[idx-2]
                    for idx, vars in effect.items():
                        # Store the dependencies of ret value into ret-node
                        if idx == 0 and isinstance(nodes[i+1], vu.Ret):
                            ret_node = nodes[i+1]
                            ret_node.dep.extend(\
                                [self.get_vid(mapping[var]) for var in vars if var in mapping])
                        if idx not in mapping: continue
                        vid = self.get_vid(mapping.get(idx))
                        if vid not in transfer:
                            transfer[vid] = []
                        transfer[vid].extend(\
                            [self.get_vid(mapping[var]) for var in vars if var in mapping])
                else:
                    print(f"TODO:{name} of blk@{block} {node}")
                    pass
                
            elif isinstance(node, vu.Call):
                for arg in node.args:
                    self.get_vid(arg)

            elif isinstance(node, vu.Jmp):
                # Just to save vid to the depended var of jmp TODO
                if node.cond:
                    for var in node.cond:
                        self.get_vid(var)

        return transfer
    
    def flow(self): # extract dataflow related to source
        def trace2set(trace:str)->set:
            blk_set = set()
            for blk in trace.split(' '):
                blk_set.add(int(blk))
            return blk_set

        candidates = set()
        target_blks = self.gen_tar_blks()
        for path in self.traces:
            blk_set = trace2set(path)
            if blk_set.intersection(target_blks):
                candidates.add(path)
        
        for path in candidates:
            blks = [int(blk) for blk in path.split(' ')]
            tainted = {}
            effected = {}
            for blk in blks:
                # Start block init
                if blk == 0:
                    for tag in self.sources:
                        tainted[tag] = [tag]
                        effected[tag] = [tag]
                    continue

                # Normal block transfer, transfer by block 
                # for var, vars in self.transfers[blk].items():
                for var, vars in self.trans[blk].items():
                    before = list(effected.keys())
                    for tvar in before:
                        if tvar in vars:
                            if var not in effected:
                                effected[var] = []
                            effected[var].append(tvar)
                            effected[var] = list(set(effected[var]))
                            if var not in tainted:
                                tainted[var] = []
                            tainted[var].extend(tainted.get(tvar))
                            tainted[var] = list(set(tainted[var]))

                # Target block check access, transfer by insn
                if blk in target_blks:
                    nodes = self.node_set.get(blk)
                    for node in nodes:
                        if isinstance(node, vu.Msg) and self.get_msgsend_name(node) in self.sink_map:
                            arglist = self.sink_map.get(self.get_msgsend_name(node))
                            succ = False
                            chains = []
                            for idx in range(len(arglist)):
                                if arglist[idx] and isinstance(node.args[idx], vu.LocalVar) \
                                    and list(self.mba.vars)[node.args[idx].idx].name in tainted:
                                    tar = list(self.mba.vars)[node.args[idx].idx].name
                                    # chains.append(self.get_taint_chain(effected, tar, tainted))
                                    succ = True
                            if succ:
                                print(f"Found {path}:\n{tainted}\n{effected}\n")
                                # print(chains)
                                return
            break