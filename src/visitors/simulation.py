import idaapi
import ida_hexrays as hr
import ida_name
import idc
import idautils

idaapi.require('visitors.unordered')
idaapi.require('visitors.sideeffects')
idaapi.require('libs.utils')
idaapi.require('libs.hint')

from .unordered import Clazz, Selector, Visitor, Assign, Arith, Msg, Call, GlobalLiteral, LocalVar, StackBlock, Factory, MemOp, Load, Store, MemObj, CFString, Op
from .sideeffects import SideEffectsRecorder, WriteOnceDetection
from libs.utils import classname, symbol, rule, tp_sanitizer

import libs.hint


class SimVisitor(Visitor):
    stack_block_isa = symbol('__NSConcreteStackBlock')
    proto_types = rule('proto')

    def __init__(self, mba):
        super().__init__(mba)
        if mba:
            self.side_effects = SideEffectsRecorder(mba).parse()
        self.local_types = {}
        self.local_vars = {}
        self.alias_map = {}
        self.snapshot = None 
        if mba:
            self.get_arg_types()

    def get_arg_types(self):
        for i in range(self.mba.argidx.size()):
            t = self.mba.arg(i).type()
            if str(t) in ['SEL', 'id']: continue
            if t.is_ptr():
                lt = str(t.get_pointed_object())
            else:
                lt = str(t)
            if lt.endswith('_meta'):
                lt = lt[:-5]
            self.local_types[i] = lt
    
    def update_local_types(self, lv:int, tp:str):
        tp = tp_sanitizer(tp)
        if not tp: return
        self.local_types[lv] = tp
        alias = lv
        while alias in self.alias_map:
            alias = self.alias_map.get(alias)
            self.local_types[alias] = tp
            if alias == self.alias_map.get(alias):
                break

    def visit_top_insn(self, insn):

        def assign_to_stkblk(stkblk:StackBlock, offset:int, var):
            if isinstance(var, LocalVar):
                stkblk.assign(offset, var)
                if var.idx in self.local_types:
                    stkblk.assign(offset, self.local_types.get(var.idx))
            elif isinstance(var, MemObj):
                if isinstance(var.base, LocalVar) and (var.base.idx in self.local_vars) \
                    and isinstance(self.local_vars.get(var.base.idx), StackBlock): # Now only support stkblk
                    val, tp = self.local_vars.get(var.base.idx).load(var.off)
                else:
                    val, tp = var.val, var.type
                stkblk.assign(offset, val)
                stkblk.assign(offset, tp)
            else:
                stkblk.assign(offset, var)
 
            lv, lt = stkblk.load(offset)
            return MemObj(stkblk, offset, lt, lv)

        expr = super().visit_top_insn(insn)

        # Transfer load and store expr into assignment
        if isinstance(expr, MemOp):
            if isinstance(expr.base, LocalVar) and (expr.base.idx in self.local_vars) \
                and isinstance(self.local_vars.get(expr.base.idx), StackBlock): # Now only support it
                expr.base = self.local_vars.get(expr.base.idx)
            if expr.memobj:
                if isinstance(expr, Load):
                    expr = Assign(expr.memobj, expr.dest)
                elif isinstance(expr, Store):
                    expr = Assign(expr.source, expr.memobj) 

        # Exclude the expr which is not an assignment
        if not isinstance(expr, Assign):
            return expr

        # Deal with Call/Msg to get the truly source
        if isinstance(expr.source, Call):
            if expr.source.func.name in libs.hint.objc_ret_as_is:
                expr.source = expr.source.args[0]
                if isinstance(expr.source, LocalVar) and isinstance(expr.dest, LocalVar):
                    self.alias_map[expr.dest.idx] = expr.source.idx
                else:
                    # mov    call $_objc_retain{12}<cdecl:id $___NSArray0__.8>.8, r12_2.8{13}
                    pass#TODO
            elif expr.source.func.name in libs.hint.objc_weak_ret:
                arg = expr.source.args[0]
                if isinstance(arg, Arith) and not(arg.dest):
                    if isinstance(arg.left, LocalVar):
                        if (arg.left.idx in self.local_vars) \
                            and isinstance(self.local_vars.get(arg.left.idx), StackBlock):
                            base = self.local_vars.get(arg.left.idx)
                            if isinstance(arg.right, Op) and (arg.right.raw.t == hr.mop_n):
                                off = arg.right.raw.value(1)
                                val, tp = base.load(off)
                                expr.source = MemObj(base, off, tp, val)
                        else:
                            base = arg.left
                            if isinstance(arg.right, Op) and (arg.right.raw.t == hr.mop_n):
                                off = arg.right.raw.value(1)
                                expr.source = MemObj(base, off, None, None)
            else:
                '''TODO
                (FBAPrivilegedClient *)objc_getProperty(self, a2, 16, 1);
                1. 0 mov    call $_objc_getProperty<cdecl:"id self" self.8,"SEL cmd" rsi0.8,"ptrdiff_t offset" #0x10.4,"bool atomic" #1.1>.8, result.8 ; 
                '''
                pass
        
        # Deal with memobj represented by arith without load
        if isinstance(expr.dest, Arith) and not(expr.dest.dest):
            arg = expr.dest
            if isinstance(arg.left, LocalVar):
                if (arg.left.idx in self.local_vars) \
                    and isinstance(self.local_vars.get(arg.left.idx), StackBlock):
                    base = self.local_vars.get(arg.left.idx)
                    if isinstance(arg.right, Op) and (arg.right.raw.t == hr.mop_n):
                        off = arg.right.raw.value(1)
                        val, tp = base.load(off)
                        expr.dest = MemObj(base, off, tp, val)
                else:
                    base = arg.left
                    if isinstance(arg.right, Op) and (arg.right.raw.t == hr.mop_n):
                        off = arg.right.raw.value(1)
                        expr.dest = MemObj(base, off, None, None)

        if isinstance(expr.dest, StackBlock):
            offset = expr.dest.raw.l.off
            expr.dest.assign(offset, expr.source)
            if isinstance(expr.source, LocalVar) and expr.source.idx in self.local_types:
                expr.dest.assign(offset, self.local_types.get(expr.source.idx))
            elif isinstance(expr.source, MemObj):
                expr.dest.assign(offset, expr.source.type)
            lv, lt = expr.dest.load(offset)
            expr.dest = MemObj(expr.dest, offset, lt, lv)

        elif isinstance(expr.dest, LocalVar):
            if (expr.dest.idx in self.local_vars) and isinstance(self.local_vars.get(expr.dest.idx), StackBlock):
                stkblk = self.local_vars.get(expr.dest.idx)
                offset = expr.dest.raw.l.off
                if offset:
                    expr.dest = assign_to_stkblk(stkblk, offset, expr.source)                    

            elif self.snapshot and (expr.dest.var.get_stkoff() >= self.snapshot.stkoff):
                offset = expr.dest.var.get_stkoff() - self.snapshot.stkoff
                expr.dest = assign_to_stkblk(self.snapshot, offset, expr.source)
            
            elif isinstance(expr.source, GlobalLiteral):
                if expr.source.ea == self.stack_block_isa:
                    layout = str(list(self.mba.vars)[expr.dest.idx].type())
                    self.local_types[expr.dest.idx] = layout
                    stkblk = StackBlock(expr.dest.idx, layout)
                    stkblk.stkoff = expr.dest.var.get_stkoff()
                    self.local_vars[expr.dest.idx] = stkblk
                    self.snapshot = stkblk
                elif not expr.dest.raw.l.off:
                    '''
                    A case: v9.receiver = self; v9.super_class = (Class)&OBJC_CLASS___OSAXPCServices;
                    mov    self.8{1}, var70.8{1}; mov    &($"_OBJC_CLASS_$_OSAXPCServices").8, var70@8.8;
                    '''
                    self.local_vars[expr.dest.idx] = expr.source 
                expr.dest.local_type = self.type_infer(expr.source)
                self.update_local_types(expr.dest.idx, expr.dest.local_type)

            elif isinstance(expr.source, LocalVar):
                offset = expr.source.raw.l.off
                if (expr.source.idx in self.local_vars) and isinstance(self.local_vars.get(expr.source.idx), StackBlock) \
                    and expr.source.raw.l.off:
                    stkblk = self.local_vars.get(expr.source.idx)
                    offset = expr.source.raw.l.off
                    lv, lt = stkblk.load(offset)
                    expr.source = lv
                # Since lv may be localvar or memobj
                if isinstance(expr.source, LocalVar):
                    if expr.source.idx in self.local_vars:
                        self.local_vars[expr.dest.idx] = self.local_vars.get(expr.source.idx)
                    elif expr.dest.idx in self.local_vars:
                        self.local_vars.pop(expr.dest.idx)
                    expr.dest.local_type = self.type_infer(expr.source)
                    self.update_local_types(expr.dest.idx, expr.dest.local_type)
                else:
                    pass

            elif isinstance(expr.source, StackBlock):
                if expr.source.layout == self.local_types[0]:
                    self.local_vars[expr.dest.idx] = self.local_vars.get(0)
                else:
                    self.local_vars[expr.dest.idx] = self.local_vars.get(expr.source.idx)
            
            else:
                expr.dest.local_type = self.type_infer(expr.source)
                self.update_local_types(expr.dest.idx, expr.dest.local_type)
                if expr.dest.idx in self.local_vars:
                    self.local_vars.pop(expr.dest.idx)

        return expr

    def visit_op(self, op):
        '''
        Since the local variables can be reused, we can not replace
        all of them by the value in local_val
        '''
        ret = super().visit_op(op)
        if isinstance(ret, LocalVar) and (ret.idx in self.local_types):
            ret.local_type = self.local_types.get(ret.idx)
        
        return ret

    def visit_insn(self, insn):
        '''
        Deal with specific insn apart first.
        '''
        def set_sel(args):
            if not isinstance(args[1], Selector):
                if isinstance(args[1], LocalVar) and (args[1].idx in self.local_vars):
                    sel = self.local_vars[args[1].idx]
                    args[1] = sel
                elif isinstance(args[1], MemObj) and (args[1].off == 0) and (args[1].base.idx in self.local_vars) \
                    and isinstance(self.local_vars.get(args[1].base.idx), Selector):
                    sel = self.local_vars.get(args[1].base.idx)
                    args[1] = sel
                # else:
                #     print(f"Error @blk {self.cur_block}: {insn._print()}")
        
        expr = None

        if insn.opcode == hr.m_call:
            '''
            TODO:
            v56[0] = _mm_unpacklo_epi64((__m128i)(unsigned __int64)CFSTR("--FBA"), (__m128i)(unsigned __int64)CFSTR("-k"));
            mov    call !_mm_unpacklo_epi64<fast:__m128i xdu.16(&($cfstr_B).8),__m128i xdu.16(&($stru_100014140).8)>.16{29}, xmm1_10.16{29}
            '''
            func = self.visit_op(insn.l)
            if isinstance(func, GlobalLiteral) and func.name.startswith('_objc_msgSend'):
                args = self.visit_op(insn.d)
                set_sel(args)
                for arg in args:
                    if isinstance(arg, LocalVar) and (arg.idx in self.local_vars) \
                        and isinstance(self.local_vars.get(arg.idx), StackBlock) and self.snapshot:
                        self.snapshot = None
                expr = Factory.make_call(func, args)
                if isinstance(expr, Msg) and isinstance(expr.selector, Selector):
                    self.infer_within_msg(expr)

            elif isinstance(func, GlobalLiteral) and \
                ((func.name in libs.hint.objc_weak_mov) or (func.name in libs.hint.objc_strong_mov)):
                args = self.visit_op(insn.d)
                src, dst = args[1], args[0]
                if isinstance(src, Arith) and not(src.dest):
                    if isinstance(src.left, LocalVar) and (src.left.idx in self.local_vars) \
                        and isinstance(self.local_vars.get(src.left.idx), StackBlock):
                        base = self.local_vars.get(src.left.idx)
                        if isinstance(src.right, Op) and (src.right.raw.t == hr.mop_n):
                            off = src.right.raw.value(1)
                            val, tp = base.load(off)
                            src = MemObj(base, off, tp, val)
                expr = Assign(src, dst)

            elif self.snapshot and isinstance(func, GlobalLiteral) and \
                (func.name.startswith('_dispatch') or func.name == '_xpc_connection_set_event_handler'\
                    or func.name == '_objc_retainBlock'):
                self.snapshot = None

        if insn.opcode == hr.m_icall and hr.get_mreg_name(insn.l.r, 2):
            if insn.r.t == hr.mop_l and self.local_vars.get(insn.r.l.idx):
                func = self.local_vars.get(insn.r.l.idx)
                args = self.visit_op(insn.d)
                if len(args)>1:
                    if func.name == '_objc_msgSend':
                        set_sel(args)
                    expr = Factory.make_call(func, args)
                    if isinstance(expr, Msg) and isinstance(expr.selector, Selector):
                        self.infer_within_msg(expr)
            # print('unhandled icall:', insn._print())

        if not expr:
            expr =  super().visit_insn(insn)

        if isinstance(expr, Load) and not(expr.dest):
            if  expr.memobj:
                if isinstance(expr.memobj.base, LocalVar) and (expr.memobj.base.idx in self.local_vars) \
                    and isinstance(self.local_vars.get(expr.memobj.base.idx), StackBlock): # Now only support stkblk
                    expr.base = self.local_vars.get(expr.memobj.base.idx)
                    expr.const = expr.memobj.off

                return expr.memobj
        
        elif isinstance(expr, Assign) and not(expr.dest):
            return expr.source

        elif isinstance(expr, Msg) or isinstance(expr, Call):
            for arg in expr.args:
                if isinstance(arg, StackBlock) and self.snapshot:
                    self.snapshot = None
                elif isinstance(arg, LocalVar) and (arg.idx in self.local_vars) and\
                    isinstance(self.local_vars.get(arg.idx), StackBlock) and self.snapshot:
                    self.snapshot = None
                elif isinstance(arg, Load):
                    idx = expr.args.index(arg)
                    expr.args[idx] = arg.memobj
            if isinstance(expr, Msg) and isinstance(expr.receiver, LocalVar)\
                and expr.receiver.idx in self.local_vars:
                expr.tp = '+'
            
        return expr

    @property
    def readable_types(self):
        return {k: str(v) for k, v in self.local_types.items()}

    def infer_within_msg(self, expr : Msg):
        def parse_proto(pt : str) -> dict:
            import re

            tp = None
            if pt[0] in ['+', '-']: tp = pt[0]

            blk = re.compile(r'\(\^\)\((?:.|\s)*?\)')
            pt = ''.join(re.split(blk, pt))
            
            if pt.startswith("@property"):
                return tp, pt.split(' ')[-1][:-1], None, pt.split(' ')[-2]

            types = re.findall(re.compile(r'[(](.*?)[)]', re.S), pt)
            for i in range(len(types)):
                types[i] = tp_sanitizer(types[i])
 
            ret = types[0]
            args = types[1:]

            parts = pt.split(':')
            tmp = [parts[i].split(' ')[-1] for i in range(1, len(parts)-1)]
            tmp.insert(0,parts[0].split(')')[-1])
            sel = ':'.join(tmp) + ':'
            
            return tp, sel, args, ret

        ret_type = None
        clazz = None
        sel = expr.selector.name
        if sel in ['performSelector:', 'performSelector:withObject:', 'performSelector:withObject:withObject:']:
            print('Warning: dynamic perform selector not implemented')
            return ret_type
        
        # Solve the receiver to get class name
        # [class] For receiver of GlobalLiteral or further Clazz Op, which we can directly get clazz name
        if isinstance(expr.receiver, GlobalLiteral):
            clazz = classname(expr.receiver.raw)
            if clazz:
                if clazz.endswith('_meta'): clazz = clazz[:-5]
                expr.recv_type = clazz
                if sel in ('new', 'alloc', 'client', 'sharedInstance', 'class'): # TODO: more
                    ret_type = clazz
                else:
                    ret_type = libs.hint.class_methods.get(clazz, {}).get(sel)
                if ret_type: return ret_type
            elif isinstance(expr.receiver, CFString):
                clazz = 'NSString'
            else:
                print(f"No class name in GlobalLiteral @{self.cur_block}: {repr(expr)}")

        # [instance] For receiver of memobj, infer clazz name
        elif isinstance(expr.receiver, MemObj):
            clazz = expr.receiver.type
        # [instance] For receiver of local var, infer clazz name
        elif isinstance(expr.receiver, LocalVar):
            clazz = self.local_types.get(expr.receiver.idx)
        
        if clazz and not(clazz == 'id'):
            expr.recv_type = clazz

        # If class name is not solved, infer it from sel; else we get (recv,sel) pair from selected prototypes
        # To void the missing of match by wrong infered class type, we traverse all the items
        for cla in self.proto_types:
            for pt in self.proto_types.get(cla):
                tp, _, args, ret = parse_proto(pt)
                if _ != sel: continue
                if tp: expr.tp = tp
                if not(clazz == cla) and not(cla == 'UNKNOWN'):
                    clazz = cla
                    expr.recv_type = clazz
                    if isinstance(expr.receiver, LocalVar):
                        expr.receiver.local_type = clazz
                        self.update_local_types(expr.receiver.idx, clazz)
                if ret == 'instancetype':
                    ret_type = clazz
                elif ret == 'ObjectType':
                    pass
                else:
                    ret_type = ret
                if args and (len(args) == len(expr.args)): 
                    for i in range(len(args)):
                        if isinstance(expr.args[i], LocalVar):
                            expr.args[i].local_type = args[i]
                            self.update_local_types(expr.args[i].idx, args[i])
                return ret_type
        
        # If no proto type is matched, check if sel is init-like method
        if sel == 'init' or sel.startswith('initWith'):
            ret_type = clazz
        else:
            ret_type = libs.hint.instance_methods.get(clazz, {}).get(sel)
            
        return ret_type

    def type_infer(self, expr)->str:
        if isinstance(expr, StackBlock):
            return expr.layout

        if isinstance(expr, Clazz):
            return expr.name
            
        if isinstance(expr, MemObj):
            return expr.type

        if isinstance(expr, LocalVar):
            return self.local_types.get(expr.idx)

        if isinstance(expr, Msg) and isinstance(expr.selector, Selector):
            ret_type = self.infer_within_msg(expr)
            if ret_type:
                return ret_type
            else:
                pass
                # print(f"Failed to infer ret type of {repr(expr)}")

        if isinstance(expr, Call) and len(expr.args):
            arg0 = expr.args[0]
            if expr.func.ea in libs.hint.arc:
                return self.type_infer(arg0)
            elif expr.func.ea in libs.hint.allocators and isinstance(arg0, GlobalLiteral):
                clazz = classname(arg0.raw)
                print(f"Not Implement: {clazz}, {expr.func.name}, {arg0.name}")
                return clazz
                # TODO:raise NotImplementedError