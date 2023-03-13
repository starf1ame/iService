import idc
import idaapi
import idautils
import ida_name
import ida_segment
import ida_bytes
import ida_funcs

idaapi.require('libs.symbols')
idaapi.require('libs.utils')
idaapi.require('libs.classdump')
idaapi.require('models.pg')
idaapi.require('visitors.unordered')
idaapi.require('intra_procedural')
idaapi.require('sinks.sinks')
idaapi.require('entries.nsxpc')
idaapi.require('entries.xpc')

from libs.utils import rule, is_dsc, genmc
from libs.classdump import ClassDump
from libs.symbols import imps, clazz2libs
from models.pg import Entry, Binary, get
from sinks.sinks import objc_sinks, c_sinks
from entries.nsxpc import find_nsxpc, find_authenticator
from entries.xpc import find_event_handlers, find_handler_setters
from intra_procedural import GraphGenerator, Sink, DataFlowExtractor
from visitors.unordered import Msg, StackBlock

class Procedure:
    def __init__(self, ea:int, name:str) -> None:
        self.ea = ea
        self.name = name
        self.caller = None
        self.graph = DataFlowExtractor(genmc(ea),None)
        self.visited = False
        self.callees = set()
        self.sinks = []
        self.is_callback = False
    
    def visit(self):
        if not self.visited:
            self.graph.visit()
            self.visited = True
    
    def __repr__(self) -> str:
        return f"<Procedure {self.name}>"

class CallGraphGenerator:
    def __init__(self, entries=None, binary=None, db=False) -> None:
        self.binary = binary
        self.entry_points = set()
        self.sensitve_func = set()
        self.xpc_entry = []
        self.db = db
        self.procedure_map: dict[str:Procedure] = {}
        self.dump = ClassDump()
        self.dump.parse()
        self.externals = {}
        if not entries:
            self.find_entry_points()
        else:
            self.make_entry_points(entries)
        self.curr_procedure = None
    
    # Generate mba for all methods dumped (not used)
    def mba_factory(self):
        worklist = []
        for clazz in self.dump.classes:
            for method in clazz.methods:
                name = f"{method[0]}[{clazz.name} {method[2:]}]"
                ea = clazz.methods[method]
                worklist.append((ea, name))
        for entry, name in worklist:
            self.procedure_map[name] = Procedure(entry, name)
    
    def find_sensitve_func(self):
        for clazz, sel, ea, xrefs, args in objc_sinks():
            for xref in xrefs:
                entry = idaapi.get_func(xref).start_ea
                name = ida_name.get_name(entry)
                sink = Sink(clazz, sel, args)
                if name in self.procedure_map:
                    self.procedure_map[name].sinks.append(sink)
                    self.sensitve_func.add(self.procedure_map.get(name))

    def make_entry_points(self, entries):
        for entry in entries:
            clazz = entry.split(' ')[0][2:]
            method = ' '.join([entry.split('[')[0],entry.split(' ')[1][:-1]])
            if (clazz in self.dump.class_lookup) and \
                (method in self.dump.class_lookup.get(clazz).methods):
                addr = self.dump.class_lookup.get(clazz).methods.get(method)
                if entry not in self.procedure_map:
                    self.procedure_map[entry] = Procedure(addr, entry)
                self.entry_points.add(self.procedure_map.get(entry))

    def find_entry_points(self):
        self.xpc_entry = list(find_event_handlers()) # Reduce re-processing
        entries = set(find_nsxpc())
        if self.db:
            session, engine = get()
            for ea in entries:
                fname = ida_name.get_name(ea)
                if session.query(Entry).filter_by(binary_path=self.binary, fname=fname).all():
                    continue
                if self.binary:
                    session.add(Entry(fname=fname, ea=hex(ea), cate='NSXPC', binary_path=self.binary))
                else:
                    session.add(Entry(fname=fname, ea=hex(ea), cate='NSXPC'))
            for handler in self.xpc_entry:
                fname = ida_name.get_name(handler)
                if session.query(Entry).filter_by(binary_path=self.binary, fname=fname).all():
                    continue
                if self.binary:
                    session.add(Entry(fname=fname, ea=hex(handler), cate='XPC', binary_path=self.binary))
                else:
                    session.add(Entry(fname=fname, ea=hex(handler), cate='XPC'))
            session.commit()
        if entries:
            auths = find_authenticator()
            if auths:
                for _, authenticator in auths:
                    entries.add(authenticator)
        for handler in self.xpc_entry:
            entries.add(handler)
        for entry in entries:
            name = ida_name.get_ea_name(entry)
            if name not in self.procedure_map:
                p = Procedure(entry, name)
                if not p.graph.mba: continue
                self.procedure_map[name] = p
            self.entry_points.add(self.procedure_map.get(name))
    
    '''
    Build call relations in binary and add involved function into procedure map
    '''
    def build_call_relations(self):
        worklist = []       # Store the name of procedures to be analyzed
        recorder = set()    # Record the procedure analyzed
        makelist = set()    # Store the names of callees of current procedure

        pairs = {}
        for handler in self.xpc_entry:
            if not list(idautils.DataRefsTo(handler)): continue
            xref = list(idautils.DataRefsTo(handler))[0]
            module_and_name = idc.get_segm_name(xref)
            if module_and_name == '__text':     # stackblock
                setter = ida_funcs.get_func(xref).start_ea
            elif module_and_name == '__const':  # globalblock
                if handler == ida_bytes.get_qword(xref + 0x10):
                    setter = ida_funcs.get_func(list(idautils.DataRefsTo(xref))[0]).start_ea
            pairs[setter] = handler
        while pairs:
            for setter, _ in list(pairs.items()):
                if setter not in pairs.values():
                    setter_name = ida_name.get_name(setter)
                    if setter_name not in self.procedure_map:
                        self.procedure_map[setter_name] = Procedure(setter, setter_name)
                    worklist.append(setter_name)
                    pairs.pop(setter)

        for p in self.entry_points:
            if p.name in worklist: continue
            worklist.append(p.name)

        while worklist:
            recorder.add(worklist[0])
            self.curr_procedure = self.procedure_map.get(worklist[0])
            print(f"Current: {self.curr_procedure}")
            nodes = []
            self.curr_procedure.visit()
            for bnodes in self.curr_procedure.graph.node_set.values():
                nodes.extend(bnodes)

            for node in nodes:
                callee_ea, callee_name = self.node_filter(node)
                if callee_name:
                    self.curr_procedure.callees.add(callee_name)
                    # In case meet the msg call cross binary
                    if callee_ea:
                        makelist.add((callee_ea, callee_name, 0))
            
            stkblk_map = {}
            lvars = self.curr_procedure.graph.local_vars
            stkblks = [lvars[idx] for idx in lvars if idx and isinstance(lvars[idx], StackBlock)]
            for blk in stkblks:
                if not blk.invoke: continue
                name = ida_name.get_ea_name(blk.invoke, 1)
                self.curr_procedure.callees.add(name)
                makelist.add((blk.invoke, name, 1))
                stkblk_map[name] = blk

            for callee_ea, callee_name, is_callback in makelist:
                if callee_name not in self.procedure_map:
                    proc = Procedure(callee_ea, callee_name)
                    if is_callback:
                        proc.is_callback = True
                    self.procedure_map[callee_name] = proc

                proc:Procedure = self.procedure_map.get(callee_name)
                proc.caller = self.curr_procedure.name

                # Propagate StkBlk into callee
                if callee_name in stkblk_map:
                    proc.graph.local_vars[0] = stkblk_map.get(callee_name).duplicate()

                if (callee_name not in recorder) and (callee_name not in worklist):
                    worklist.append(callee_name)      

            makelist.clear()
            worklist.pop(0)

        self.curr_procedure = None

    '''
    Only ret msgsend with known clazz&sel
    '''
    def node_filter(self, node) -> str:
        if isinstance(node, Msg):
            name = self.curr_procedure.graph.get_msgsend_name(node)
            if not name:
                return None, None
            clazz = name.split(' ')[0][2:]
            sel = name.split(' ')[1][:-1]
            if clazz in self.dump.class_lookup.keys():
                methods = self.dump.class_lookup[clazz].methods
                for method, ea in methods.items():
                    if sel == method[2:]:
                        return ea, name
            # Means the msg is cross binary from outside
            else: 
                if (clazz in clazz2libs) and not(clazz.startswith('NS')):
                    lib_path = clazz2libs.get(clazz)
                    if not lib_path in self.externals:
                        self.externals[lib_path] = []
                    self.externals[lib_path].append(name)
                return None, name
        return None, None
    
    '''
    Store external calls into sql as entries of frameworks
    '''
    def dump_externals(self):
        session, engine = get()
        for lib, fnames in self.externals.items():
            if not(session.query(Binary).filter_by(path=lib).all()):
                session.add(Binary(path=lib, cate='framework'))
            for fname in fnames:
                if not(session.query(Entry).filter_by(fname=fname).all()):
                    if not self.binary:
                        session.add(Entry(fname=fname, binary_path=lib, cate='external'))
                    else:
                        session.add(Entry(fname=fname, binary_path=lib, caller=self.binary, cate='external'))
        
        session.commit()
    
    '''
    Store call graph in a structure can be pickled
    '''
    def dump_callgraph(self):
        cg = CallGraph()
        for entry in self.entry_points:
            cg.entry_points.append(entry.name)
        
        for fname in self.procedure_map:
            proc = self.procedure_map.get(fname)
            item = {}
            item['is_callback'] = proc.is_callback
            item['callees'] = list(proc.callees)
            item['caller'] = proc.caller
            item['ea'] = proc.graph.mba.entry_ea
            cg.procedure_map[fname] = item
        
        return cg


class CallGraph:
    def __init__(self) -> None:
        self.entry_points = []
        self.procedure_map = {}