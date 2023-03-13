'''
this visitor iterates all instructions and operands,
without considering the execution flow or data flow
'''

import idc
import idaapi
import ida_name
import ida_bytes
import ida_hexrays as hr

insn_map = {getattr(hr, attr): attr for attr in dir(hr)
            if attr.startswith('m_')}
op_map = {getattr(hr, attr): attr for attr in dir(hr)
          if attr.startswith('mop_')}


idaapi.require('libs.utils')
from libs.utils import *
import libs.hr


class Node:
    pass


class Call(Node):
    def __init__(self, func, args):
        self.func = func
        self.args = list(args)
        self.name = ida_name.get_name(func.ea)

    def __repr__(self):
        return '<Call to %s>' % self.name


class Op:
    def __init__(self, op):
        self.raw = op

    def __repr__(self):
        return '<%s %s>' % (self.__class__.__name__, op_map[self.raw.t])


class LocalVar(Op):
    def __init__(self, op):
        super().__init__(op)
        self.name = op.l.var().name
        self.vid = None
        self.local_type = None

    @property
    def idx(self):
        return self.raw.l.idx

    @property
    def var(self):
        return self.raw.l.var()


class StackVar(LocalVar):
    def __init__(self, op):
        super().__init__(op)


class RegVar(LocalVar):
    def __init__(self, op):
        super().__init__(op)
        self.offset = op.l.var().get_stkoff()


class GlobalLiteral(Op):
    def __init__(self, op):
        super().__init__(op)

    @property
    def ea(self):
        return self.raw.g

    @property
    def name(self):
        return ida_name.get_name(self.ea)

class Clazz(GlobalLiteral):
    def __init__(self, op):
        super().__init__(op)
    
    @property
    def name(self):
        return classname(self.raw)
    
    def __repr__(self):
        return classname(self.raw)

class Selector(GlobalLiteral):
    def __init__(self, op, ea):
        super().__init__(op)
        self.sel_name = cstr(ea)

    @property
    def name(self):
        return self.sel_name

    def __repr__(self):
        return self.name


class GlobalBlock(GlobalLiteral):
    isa = symbol('__NSConcreteGlobalBlock')

    def __init__(self, op):
        super().__init__(op)
        self.invoke = ida_bytes.get_qword(self.ea + 0x10)


class Msg(Node):
    def __init__(self, receiver: Op, selector: Selector, *args):
        self.receiver = receiver
        self.selector = selector
        self.args = list(args)
        self.ret_type = None
        self.recv_type = None
        self.sel_val = None #TODO
        self.name = None
        self.tp = None # '-' or '+'

    def __repr__(self):
        if self.recv_type:
            return '<Msg [%s %s]>' % (self.recv_type, self.selector)
        else:
            return '<Msg [%s %s]>' % (self.receiver, self.selector)

class Ret(Node):
    def __init__(self, tp, val, dep):
        self.tp = tp
        self.val = val
        if dep:
            self.dep = dep
        else:
            self.dep = []

    def __repr__(self) -> str:
        return f'<Ret: type is {self.tp}, value is {self.val}, deps on {self.dep}'

class StackBlock:
    raw = None  # current assign instruction

    def __init__(self, idx, layout=None):
        self.idx = idx
        # Default to be native in current context
        self.native = True
        self.layout = layout
        self.stkoff = None
        self.isa = 0
        self.invoke = 0
        self.lvars = {}
        self.lvar_type = {}
        self.lvar_count = 0

    def assign(self, offset, val):
        if offset % 8: return
        index = offset >> 3
        if index == 0:
            try:
                self.isa = val.ea
            except:
                pass
        elif index == 1:
            return  # flags
        elif index == 2:
            try:
                self.invoke = val.ea
            except:
                pass
        elif index == 3:
            return  # descriptor
        else:
            lvar_index = index - 3
            if lvar_index > self.lvar_count:
                self.lvar_count = lvar_index
            if isinstance(val, str):
                self.lvar_type[lvar_index] = val
            else:
                self.lvars[lvar_index] = val

    def load(self, offset):
        if offset %8: return None,None
        index = offset >> 3
        lvar, lvar_type = None, None
        if index >= 3:
            lvar_index = index - 3
            if self.native and lvar_index in self.lvars:
                lvar = self.lvars.get(lvar_index)
            if lvar_index in self.lvar_type:
                lvar_type = self.lvar_type.get(lvar_index)
        return lvar, lvar_type

    def duplicate(self):
        dupStkblk = StackBlock(0, self.layout)
        # Set native to false since it will pass to the invoke func
        dupStkblk.native = False
        dupStkblk.isa = self.isa
        dupStkblk.invoke = self.invoke
        dupStkblk.lvar_count = self.lvar_count
        dupStkblk.lvar_type = self.lvar_type
        
        return dupStkblk

class StringLiteral(GlobalLiteral):
    def __init__(self, op):
        super().__init__(op)
        self.str = cstr(self.ea)

    def __str__(self):
        return self.str

    def __repr__(self):
        return '"%s"' % self.str


class CFString(GlobalLiteral):
    def __init__(self, op):
        super().__init__(op)
        self.str = cstr(ida_bytes.get_qword(self.ea + 0x10))

    def __repr__(self):
        return '@"%s"' % self.str


class Assign(Node):
    def __init__(self, src, dst):
        self.source = src
        self.dest = dst
    
    def __repr__(self) -> str:
        return f"<Assign from {self.source} to {self.dest}>"

class Reg(Op):
    def __init__(self, op):
        super().__init__(op)
        self.name = op.dstr().split('.')[0]

    def __repr__(self):
        return self.name

class MemObj:
    def __init__(self, base, off, tp, val):
        self.base = base
        self.off = off
        self.type = tp
        self.val = val
        self.vid = None

    def __repr__(self)->str:
        return f"{self.base}+{self.off}"

class MemOp(Node):
    def __init__(self, sel, off):
        self.selector = sel
        self.offset = off
        self.base = None
        self.const = -1
        
        # Solve the base of memobj
        if isinstance(self.offset, LocalVar):
            self.base = self.offset
            self.const = 0
        elif isinstance(self.offset, Call) or isinstance(self.offset, Msg):
            self.base = self.offset
            '''
            <Assign from <Call to ___error>+0 to <RegVar mop_l>>
            in such case, we don't use memobj, since <Call to ___error>+0 cannot be represented by vid
            '''
        elif isinstance(self.offset, Arith):
            if isinstance(self.offset.left, LocalVar) or \
                isinstance(self.offset.left, StackBlock) or isinstance(self.offset.left, MemObj):
                self.base = self.offset.left
            elif isinstance(self.offset.left, Arith):
                sub_bases = self.offset.left.ops
                self.base = sub_bases
        elif isinstance(self.offset, MemObj):
            self.base = self.offset
            self.const = 0
        else: 
            self.base = None # TODO: other situations?

        # Solve the offset of memobj
        if isinstance(self.offset, Op):
            self.const = 0
        elif isinstance(self.offset, Arith) and isinstance(self.offset.right, Op)\
            and (self.offset.right.raw.t == hr.mop_n):
            self.const = self.offset.right.raw.value(1)
    
    @property
    def memobj(self):
        tp, val = None, None
        if self.const > -1:
            if self.base:
                if isinstance(self.base, StackBlock):
                    val, tp = self.base.load(self.const)                
                return MemObj(self.base, self.const, tp, val)
        elif self.base and isinstance(self.offset, Arith):
            if isinstance(self.offset.right, LocalVar):
                return MemObj(self.base, [self.offset.right], tp, val)
            elif isinstance(self.offset.right, Arith):
                return MemObj(self.base, self.offset.right.ops, tp, val)

        print(f"Failed on memobj offset {self.offset} of base {self.base}")

    def __repr__(self) -> str:
        return f"<MemOp on {self.selector}[{self.offset}]"

class Load(MemOp):
    def __init__(self, sel, off, dst):
        super().__init__(sel, off)
        self.dest = dst
    
    def __repr__(self) -> str:
        return f"<Load from {self.selector}[{self.offset}] to {self.dest}"

class Store(MemOp):
    def __init__(self, src, sel, off):
        super().__init__(sel, off)
        self.source = src

    def __repr__(self) -> str:
        return f"<Store from {self.source} to {self.selector}[{self.offset}]"


class Arith(Node):
    def __init__(self, left, right, dst, tp):
        if isinstance(left, Load):
            self.left = left.memobj
        else:
            self.left = left
        self.right = right
        self.dest = dst
        self.tp = tp
    
    @property
    def ops(self):
        ret = []
        if isinstance(self.left, Arith):
            ret.extend(self.left.ops)
        elif isinstance(self.left, LocalVar):
            ret.append(self.left)
        if isinstance(self.right, Arith):
            ret.extend(self.right.ops)
        elif isinstance(self.right, LocalVar):
            ret.append(self.right)
        
        return ret

    def __repr__(self) -> str:
        return f"<Arithmetic on {self.left} and {self.right} to {self.dest}"

class Jmp(Node):
    def __init__(self, jtp, cond, dst):
        self.jtp = jtp
        self.cond = cond
        self.dest = dst
    
    def __repr__(self) -> str:
        return f"Jump to blk@{self.dest} by conditions: {self.cond}"

class Unhandled:
    def __init__(self, l, d, r, insn):
        self.l, self.d, self.r, self.raw = l, d, r, insn


class Factory:
    @staticmethod
    def make_local(op):
        v = op.l.var()
        if v.is_reg_var():
            return RegVar(op)
        elif v.is_stk_var():
            return StackVar(op)
        else:
            raise ValueError(
                'Unknown type of local variable: %s' % op._print())

    @staticmethod
    def make_global(op):
        ea = op.g
        module_and_name = idc.get_segm_name(ea)
        seg = module_and_name[module_and_name.find(':') + 1:]
        if seg == '__OBJC_RO':
            return Selector(op, ida_bytes.get_qword(ea))

        elif seg == '__objc_methname':
            return Selector(op, ea)

        elif seg == '__objc_selrefs':
            xref = list(idautils.DataRefsFrom(ea))[0]
            sub_module_and_name = idc.get_segm_name(xref)
            sub_seg = sub_module_and_name[module_and_name.find(':') + 1:]
            if sub_seg == '__objc_methname':
                return Selector(op, xref)

        elif seg == '__const' and ida_bytes.get_qword(ea) == GlobalBlock.isa:
            return GlobalBlock(op)

        elif seg == '__cfstring':
            return CFString(op)

        elif seg == '__cstring':
            return StringLiteral(op)
        
        # todo: imported Symbol, Class, Protocol
        # todo: UNDEF, __stubs
        elif (seg == 'UNDEF' and is_class_ref(ea))\
            or (seg == '__objc_data' and is_class_ref(ea)):
            return Clazz(op)
        # print(op._print(), seg)
        # in __stubs: _objc_retainAutoreleasedReturnValue ...

        return GlobalLiteral(op)

    @staticmethod
    def make_call(func, args):
        if not isinstance(func, GlobalLiteral):
            # todo: handle helper
            if func.raw.t == hr.mop_h:
                print('todo:', func.raw._print())
                return None

            raise ValueError('Invalid function: %s' % func)

        if func.name.startswith('_objc_msgSend'):
            __self, sel, *rest = args
            return Msg(__self, sel, *rest)
        return Call(func, args)
    
    @staticmethod
    def make_ret(tp, val, dep):
        return Ret(tp, val, dep)
    
    @staticmethod
    def make_reg(op):
        return Reg(op)


class Visitor:
    def __init__(self, mba):
        self.mba = mba
        self.cur_block = -1

        # stack block literals
        # mark_stack_blocks(mba.entry_ea) mov to mcgen

    def visit(self):
        for i in range(1, self.mba.qty):
            mblock = self.mba.get_mblock(i)
            self.cur_block = i
            self.visit_block(mblock)
            self.cur_block = -1

    def visit_block(self, mblock):
        insn = mblock.head
        while insn:
            self.visit_top_insn(insn)
            insn = insn.next

    def visit_top_insn(self, insn):
        return self.visit_insn(insn)

    def visit_insn(self, insn):
        l = self.visit_op(insn.l)
        d = self.visit_op(insn.d)
        r = self.visit_op(insn.r)

        if (insn.opcode in libs.hr.m_mov_like): # and (insn.d.t == hr.mop_l):
            if isinstance(d, StackBlock):
                d.raw = insn.d
            return Assign(l, d)

        if (insn.opcode in libs.hr.m_arithmetic):
            tp = None
            tps = {
                'm_add':'+',
                'm_sub':'-',
                'm_mul':'*',
            }
            if insn.opcode in tps:
                tp = tps.get(insn.opcode)
            
            return Arith(l, r, d, tp)

        if insn.opcode == hr.m_ldx:
            return Load(l, r, d)
        
        if insn.opcode == hr.m_stx:
            return Store(l, r, d)

        if insn.opcode == hr.m_call:
            return Factory.make_call(l, d)

        if insn.opcode in libs.hr.m_jmp:
            if not insn.opcode in libs.hr.m_jmp1:
                jtp = insn.opcode # insn_map.get(insn.opcode)
                if insn.opcode in libs.hr.m_jmp0:
                    conds = None
                    dest = l
                elif insn.opcode in libs.hr.m_jmp2:
                    conds = [l, r]
                    dest = d
                return Jmp(jtp, conds, dest)
            else:
                pass            

        # todo: handle by subclasses
        return Unhandled(l, d, r, insn)

    def visit_op(self, op):
        if op.t == hr.mop_z:
            return

        if op.t == hr.mop_a:
            return self.visit_op(op.a)

        if op.t == hr.mop_f:
            return [self.visit_op(a) for a in op.f.args]

        if op.t == hr.mop_d:
            return self.visit_insn(op.d)

        if op.t == hr.mop_v:
            return Factory.make_global(op)

        if op.t == hr.mop_l:
            return Factory.make_local(op)

        if op.t == hr.mop_b:
            return op.b

        if op.t == hr.mop_r:
            return Factory.make_reg(op)

        return Op(op)
