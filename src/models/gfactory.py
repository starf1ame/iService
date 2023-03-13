import visitors.unordered as vu
from models.graph import *

class gFactory:
    @staticmethod
    def make_statement(insn, bfloc):
        stn = None
        binary, fname, loc = bfloc.split('$')[0], bfloc.split('$')[1], bfloc.split('$')[2]
        floc = bfloc.split('$', 1)[-1]

        if isinstance(insn, vu.Msg):
            stn = gMsg()
            stn.cate = "MsgSend"
            stn.recv_type = insn.recv_type
            stn.name = insn.name
            stn.ret_type = insn.ret_type
            rev = gFactory.make_operand(insn.receiver, fname, binary)
            if rev: stn.recv.add(rev)

        elif isinstance(insn, vu.Call):
            stn = gCall()
            stn.cate = "Call"
            stn.name = insn.name

        elif isinstance(insn, vu.Assign):
            if not insn.dest: return
            stn = gAssign()
            stn.cate = "Assignment"
            src = gFactory.make_operand(insn.source, fname, binary)
            dst = gFactory.make_operand(insn.dest, fname, binary)
            if src: stn.source.add(src)
            if dst: stn.dest.add(dst)

        elif isinstance(insn, vu.Arith):
            if insn.dest:
                stn = gArith()
                stn.cate = "Arithmetic"
                if insn.tp:
                    stn.tp = insn.tp
                left = gFactory.make_operand(insn.left, fname, binary)
                right = gFactory.make_operand(insn.right, fname, binary)
                dst = gFactory.make_operand(insn.dest, fname, binary)
                if left: stn.source.add(left)
                if right: stn.source.add(right)
                if dst: stn.dest.add(dst)

        elif isinstance(insn, vu.Jmp):
            stn = gJmp()
            stn.cate = "Jump"
            stn.dest = insn.dest
            stn.func_dep = []
            if insn.cond:
                stn.is_goto = 0
                for var in insn.cond:
                    # Deal with: jz low.1(call $_objc_msgSend<...>.8), #0.1, @8
                    if isinstance(var, vu.Assign) and not var.dest:
                        var = var.source
                    if isinstance(var, vu.Call) or isinstance(var, vu.Msg):
                        stn.func_dep.append(var.name)
                    op = gFactory.make_operand(var, fname, binary)
                    if op: stn.conditions.add(op)
            else: stn.is_goto = 1

        elif isinstance(insn, vu.Unhandled):
            stn = gUnhandled()
            stn.raw = insn.raw.dstr()

        elif not insn:
            stn = gEnd()
            stn.cate = 'End'

        if stn: 
            stn.location = floc
            stn.func = fname
            stn.binary = binary
            stn.block = int(loc.split('_')[0])

            if isinstance(stn, gCall) or isinstance(stn, gMsg):
                func = Func()
                func.name = stn.name
                func.binary = binary
                stn.callee.add(func)
                
                ret = gRet()
                ret.callsite = stn.location
                stn.ret.add(ret)

                for arg in insn.args:
                    op = gFactory.make_operand(arg, fname, binary)
                    if op: stn.args.add(op, argidx=insn.args.index(arg))

        return stn
        

    @staticmethod
    def make_operand(var, fname, binary):
        import ida_hexrays as hr

        op = None
        if isinstance(var, vu.LocalVar):
            op = gLocalVar()
            if not var.vid: print(var, var.name)
            op.vid = '$'.join([fname,var.vid])
            op.name = var.name
            op.local_type = var.local_type
            # Connect the local var and corresponding stackblock
            if op.local_type and op.local_type.startswith('Block_layout_'):
                blk = gStkBlk()
                blk.layout = '$'.join([fname, op.local_type])
                op.alias.add(blk)

        elif isinstance(var, vu.MemObj):
            if not var.vid:
                print(f'[WARNING] Missing vid of {var} in {fname}')
                return
            op = gMemObj()
            op.vid = '$'.join([fname,var.vid])
            op.off = var.vid.rsplit('_', 1)[-1]
            if isinstance(var.base, list):
                base = gFactory.make_operand(var.base[0], fname, binary)
            else:
                base = gFactory.make_operand(var.base, fname, binary)
                if isinstance(var.base, vu.StackBlock):
                    _, tp = var.base.load(int(op.off))
                    if tp: op.local_type = tp
            op.base.add(base)

        elif isinstance(var, vu.StackBlock):
            op = gStkBlk()
            op.layout = '$'.join([fname, var.layout])

        elif isinstance(var, vu.GlobalLiteral):
            op = gGlobalLiteral()
            op.ea = var.ea
            op.name = var.name

        elif isinstance(var, vu.Op) and (var.raw.t == hr.mop_n):
            op = gConst()
            
            if var.raw.is_positive_constant():
                op.value = var.raw.value(1)
            elif var.raw.is_negative_constant():
                op.value = -((var.raw.value(1)-1)^0xffffffffffffffff)
            else:
                op.value = 0

        if op:
            op.binary = binary
            op.func = fname

        return op