import idc
import idaapi
import idautils
import ida_funcs
import ida_bytes
import ida_range
import ida_nalt
import ida_name
import ida_segment
import ida_hexrays as hr


def genmc(ea, maturity=hr.MMAT_LVARS):
    mark_stack_blocks(ea)
    f = ida_funcs.get_func(ea)
    if not f: return None
    if not ida_bytes.is_code(ida_bytes.get_flags(f.start_ea)):
        raise ValueError('invalid ea 0x%x' % ea)

    hf = hr.hexrays_failure_t()
    mbr = hr.mba_ranges_t()
    mbr.ranges.push_back(ida_range.range_t(f.start_ea, f.end_ea))
    mba = hr.gen_microcode(mbr, hf, None, hr.DECOMP_WARNINGS |
                           hr.DECOMP_NO_CACHE, maturity)
    return mba


def mark_stack_blocks(ea):
    run_objc_plugin(ea, 5)


def has_macsdk():
    import subprocess
    from pathlib import Path
    try:
        s = subprocess.check_output(
            ['xcrun', '--show-sdk-path']).strip().decode()
        return Path(s).exists()
    except:
        return False


def load_header():
    # load function prototypes
    if idaapi.IDA_SDK_VERSION < 750 or not has_macsdk():
        from pathlib import Path
        header = str(Path(__file__).parent.parent /
                     'IDAObjcTypes' / 'IDA.h')
        idaapi.idc_parse_types(header, idc.PT_FILE)


def cstr(ea):
    try:
        return ida_bytes.get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C).decode()
    except Exception as e:
        print('Unable to decode string at %s' % hex(ea))
        raise e


def symbol(name):
    return ida_name.get_name_ea(idc.BADADDR, name)


def is_class_ref(ea):
    # todo: dsc
    for xref in idautils.DataRefsTo(ea):
        seg = ida_segment.getseg(xref)
        seg_name = ida_segment.get_segm_name(seg)
        if seg_name == '__objc_classrefs':
            return True

    return False


# TODO:error designing here
def is_imported_class_ref(ea):
    seg = ida_segment.getseg(ea)
    seg_name = ida_segment.get_segm_name(seg)
    return seg_name == 'UNDEF'


def classname(op):
    # todo: check op type
    ea = op.g
    if is_class_ref(ea) or is_imported_class_ref(ea):
        return ida_name.get_ea_name(ea)[len('_OBJC_CLASS_$_'):]


def rule(name: str):
    import yaml
    from pathlib import Path
    filename = Path(__file__).parent.parent / 'rules' / (name + '.yaml')
    with filename.open() as fp:
        return yaml.load(fp, Loader=yaml.FullLoader)


def is_dsc():
    return bool(ida_segment.get_segm_by_name('Foundation:__objc_selrefs'))


'''
Example for summary (en/de)coder
[6,2,4,6] means:
       ret recv arg0 arg1
ret     0    0    0    0  (always 0)
recv    1    0    1    1
arg0    1    1    0    1
arg1    0    0    0    0
sum     6    2    4    6
The metric indicates:
* ret(0) is effected by recv(1) and arg0(2)
* recv(1) is effected by arg0(2)
* arg0(2) is effected by recv(1)
* arg1(3) is effected by recv(1) and arg0(2)
'''

def encode_summary(dep : dict) -> list:
    summary = []
    l = len(dep.keys())
    for _, vars in dep.items():
        tmp = 0
        for var in vars:
            tmp += 2**(l-var-1)
        summary.append(tmp)
    
    return summary


def decode_summary(summary : list) -> dict:
    l = len(summary) - 1
    dep = {}
    for i in range(len(summary)):
        dep[i] = []
        item = f"{{:0{l}b}}".format(summary[i])
        for j in range(l):
            if int(item[j]):
                dep[i].append(j+1)
    
    return dep


nullability_annotations = [
    'nonnull',
    'nullable',
    '__nonnull',
    '__nullable',
    '_Nonnull',
    '_Nullable'
]


def tp_sanitizer(tp : str) -> str:
    if not tp: return
    if not isinstance(tp, str): return
    if 'const' in tp:
        tp = ''.join(tp.split('const'))
    for anno in nullability_annotations:
        if anno not in tp: continue
        tp = ''.join(tp.split(anno))
        break
    # Fill out conformed protocol, e.g., 'id<NSCopying>', 'NSDictionary<KeyType, ObjectType>'
    if "<" in tp:
        tp = tp[:tp.index("<")]
    # No need for pointer, e.g., 'NSFastEnumerationState *'
    if "*" in tp:
        tp = tp[:tp.index("*")-1]
    tp = tp.replace(' ', '')
    if tp in ['ObjectType', 'KeyType', 'id']:
        return None
    if tp.endswith('_meta'):
        tp = tp[:-5]
    return tp


def run_objc_plugin(ea, opt):
    '''
    opt = 1: parse all Objective-C type information embedded in the binary
    opt = 2: calculate the address of method that is being invoked
    opt = 3: analyze objc info for a specific library
    opt = 4: perform global block analysis on a specific function
    opt = 5: perform stack block analysis on a specific function
    '''
    n = idaapi.netnode()
    n.create("$ objc")
    n.altset(1, ea, 'R')
    ret = idaapi.load_and_run_plugin("objc", opt)
    return ret


def get_summary(summary_set:dict, fname:str):
    if fname in summary_set:
        return summary_set.get(fname)
    placeholder = "UNKNOWN"
    prefix = fname.split(' ')[0].split('[')[0] + placeholder
    unk_fname = ''.join([prefix, fname.split(' ')[-1]])
    if unk_fname in summary_set:
        return summary_set.get(unk_fname)
    
    return None