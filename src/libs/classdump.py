import struct
from collections import namedtuple

import idc
import ida_nalt
import idaapi
import ida_segment
import ida_bytes


def cstr(ea):
    try:
        return ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C).decode()
    except Exception as e:
        print('Unable to decode string at %s' % hex(ea))
        raise e


class Objc2Class(object):
    """
    struct __objc2_class
    {
        __objc2_class *isa;
        __objc2_class *superclass;
        void *cache;
        void *vtable;
        __objc2_class_ro *info;
    };
    """
    fmt = '<QQQQQ'
    length = struct.calcsize(fmt)

    def __init__(self, data, offset=0):
        (self.isa,
         self.superclass,
         self.cache,
         self.vtable,
         self.info) = struct.unpack_from(self.fmt, data, offset)


class Objc2ClassRo(object):
    """
    struct __objc2_class_ro
    {
        uint32_t flags;
        uint32_t ivar_base_start;
        uint32_t ivar_base_size;
        uint32_t reserved;
        void *ivar_lyt;
        char *name;
        __objc2_meth_list *base_meths;
        __objc2_prot_list *base_prots;
        __objc2_ivar_list *ivars;
        void *weak_ivar_lyt;
        __objc2_prop_list *base_props;
    };
    """
    fmt = '<IIIIQQQQQQQ'
    length = struct.calcsize(fmt)

    def __init__(self, data, offset=0):
        (self.flags,
         self.ivar_base_start,
         self.ivar_base_size,
         self.reserved,
         self.ivar_lyt,
         self.name,
         self.base_meths,
         self.base_prots,
         self.ivars,
         self.weak_ivar_lyt,
         self.base_props) = struct.unpack_from(self.fmt, data, offset)


class Objc2Method(object):
    fmt = '<QQQ'
    length = struct.calcsize(fmt)

    def __init__(self, data, offset=0):
        (self.name, self.types, self.imp) = struct.unpack_from(
            self.fmt, data, offset)


Post14Method = namedtuple('Method', ['name', 'types', 'imp'])


def method_list(ea):
    if not ea:
        return

    count = ida_bytes.get_dword(ea + 4)
    name = idc.get_segm_name(ea)
    first = ea + 8

    def post14format(addr):
        for _ in range(3):
            data = ida_bytes.get_bytes(addr, 4)
            offset, = struct.unpack('<i', data)
            yield addr + offset
            addr += 4

    is14 = name and (name.endswith(':__objc_const_ax')
                     or name.endswith(':__objc_methlist'))
    for i in range(count):
        if is14:
            # iOS 14
            yield Post14Method(*post14format(first + i * 12))

        else:
            ea_method_t = first + i * Objc2Method.length
            data = ida_bytes.get_bytes(ea_method_t, Objc2Method.length)
            yield Objc2Method(data)


class Base(object):
    def __init__(self, name, ea):
        self.name = name
        self.ea = ea

    def __repr__(self):
        return '<%s "%s">' % (self.__class__.__name__, self.name)


class Clazz(Base):
    def __init__(self, name, ea):
        super().__init__(name, ea)
        self.methods = {}


class Protocol(Base):
    def __init__(self, name, ea):
        super().__init__(name, ea)
        self.methods = []


class ClassDump(object):
    def __init__(self, output=None, verbose=False):
        self.classes = []
        self.protocols = []
        self.class_lookup = {}
        self.protocol_lookup = {}
        self.lookup = {}
        self.output = output
        self.verbose = verbose

    def print(self, *args):
        if self.output is not None:
            print(*args, file=self.output)
        elif self.verbose:
            print(*args)

    def parse(self):
        if ida_segment.get_segm_by_name('DYLD_CACHE_HEADER'):
            seg = ida_segment.get_first_seg()

            def handle(seg):
                name = ida_segment.get_segm_name(seg)
                try:
                    _, segname = name.split(':')
                except ValueError:
                    return

                if segname == '__objc_protolist':
                    self.handle_proto_seg(seg)
                elif segname == '__objc_classlist':
                    self.handle_class_seg(seg)

            while seg:
                handle(seg)
                seg = ida_segment.get_next_seg(seg.start_ea)

            return

        protocols = ida_segment.get_segm_by_name('__objc_protolist')
        if protocols:
            self.handle_proto_seg(protocols)

        classes = ida_segment.get_segm_by_name('__objc_classlist')
        if classes:
            self.handle_class_seg(classes)

    def handle_proto_seg(self, protocols):
        for ea in range(protocols.start_ea, protocols.end_ea, 8):
            self.handle_protocol(ea)

    def handle_class_seg(self, classes):
        for ea in range(classes.start_ea, classes.end_ea, 8):
            self.handle_class(ea)

    def handle_protocol(self, ea):
        protocol_ea = ida_bytes.get_qword(ea)
        p = parse_protocol(protocol_ea)
        self.print('@protocol', p.name)
        for method in p.methods:
            self.print(method)
        self.print('@end')
        self.print()
        self.protocols.append(p)
        self.protocol_lookup[p.name] = p
        self.lookup[ea] = p

    def handle_class(self, ea):
        clazz_ea = ida_bytes.get_qword(ea)
        c = parse_class(clazz_ea)
        self.print('@interface', c.name)

        for key in c.methods:
            self.print(key)

        self.print('@end')
        self.print()

        self.classes.append(c)
        self.class_lookup[c.name] = c
        self.lookup[ea] = c


def parse_class(ea):
    clazz = Objc2Class(ida_bytes.get_bytes(ea, Objc2Class.length))
    # if clazz.info & 7 != 0:
    # swift

    meta_class = Objc2Class(
        ida_bytes.get_bytes(clazz.isa, Objc2Class.length))
    meta_class.info = (meta_class.info >> 3) << 3
    meta_info = Objc2ClassRo(ida_bytes.get_bytes(
        meta_class.info, Objc2ClassRo.length))

    clazz.info = (clazz.info >> 3) << 3
    clazz_info = Objc2ClassRo(ida_bytes.get_bytes(
        clazz.info, Objc2ClassRo.length))

    c = Clazz(cstr(clazz_info.name), ea=ea)
    for method in method_list(meta_info.base_meths):
        key = '+ ' + cstr(method.name)
        c.methods[key] = method.imp

    for method in method_list(clazz_info.base_meths):
        key = '- ' + cstr(method.name)
        c.methods[key] = method.imp

    return c


def parse_protocol(ea):
    protocol_name = cstr(ida_bytes.get_qword(ea + 8))
    method_list_ea = ida_bytes.get_qword(ea + 3 * 8)
    p = Protocol(protocol_name, ea=ea)

    # todo: support class methods
    for method in method_list(method_list_ea):
        key = '- ' + cstr(method.name)
        p.methods.append(key)

    return p
