import idc
import idaapi
import idautils
import ida_funcs

idaapi.require('libs.utils')
idaapi.require('visitors.unordered')
idaapi.require('visitors.simulation')

from libs.utils import genmc, has_macsdk, load_header, symbol
import visitors.unordered as vu
import visitors.simulation as vs

set_handler = symbol('_xpc_connection_set_event_handler')
create_service = symbol('_xpc_connection_create_mach_service')
create_listener = symbol('_xpc_connection_create_listener')


class NameFinder(vs.SimVisitor):
    def __init__(self, mba, target):
        super().__init__(mba)
        self.target = target
        self.names = set()

    def visit_insn(self, insn):
        expr = super().visit_insn(insn)
        if isinstance(expr, vu.Call) and expr.func.ea == self.target and len(expr.args) > 1:
            arg0 = expr.args[0]
            if isinstance(arg0, vu.StringLiteral):
                self.names.add(str(arg0))
            elif isinstance(arg0, vu.LocalVar):
                if isinstance(self.local_vars.get(arg0.idx), vu.StringLiteral):
                    self.names.add(self.local_vars.get(arg0.idx))


class HandlerFinder(vu.Visitor):
    def __init__(self, mba):
        super().__init__(mba)

        # must run a pass first to resolve block literals
        self.sim = vs.SimVisitor(mba)
        self.handlers = set()

    def visit(self):
        self.sim.visit()
        super().visit()

    def visit_insn(self, insn):
        expr = super().visit_insn(insn)
        if isinstance(expr, vu.Call) and expr.func.ea == set_handler:
            if len(expr.args) < 2:  # invalid ast
                return expr

            block = expr.args[1]
            if isinstance(block, vu.LocalVar):
                block_info = self.sim.local_vars.get(block.idx)
                if isinstance(block_info, vu.StackBlock):
                    self.handlers.add(block_info.invoke)

            elif isinstance(block, vu.GlobalBlock):
                self.handlers.add(block.invoke)


def find_names():
    for creator in [create_listener, create_service]:
        if creator == idc.BADADDR:
            continue

        for xref in idautils.CodeRefsTo(creator, False):
            mba = genmc(xref)
            visitor = NameFinder(mba, creator)
            visitor.visit()
            yield from visitor.names


def find_handler_setters():
    if set_handler == idc.BADADDR:
        return

    for xref in idautils.CodeRefsTo(set_handler, False):
        yield ida_funcs.get_func(xref).start_ea


def find_event_handlers():
    if set_handler == idc.BADADDR:
        return

    for xref in idautils.CodeRefsTo(set_handler, False):
        mba = genmc(xref)
        visitor = HandlerFinder(mba)
        visitor.visit()
        yield from visitor.handlers


if __name__ == '__main__':
    idaapi.require('batch')
    from batch import BatchMode

    with BatchMode():
        if not has_macsdk():
            load_header()

        for handler in find_event_handlers():
            print(hex(handler), idaapi.get_func_name(handler))

        for name in find_names():
            print(name)
