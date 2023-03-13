import idc
import idaapi

idaapi.require('libs.utils')
from libs.utils import symbol

# todo:

instance_methods = {
    'NSXPCListener': {
        'initWithMachServiceName:': 'NSXPCConnection',
        'initWithMachServiceName:options:': 'NSXPCConnection',
    }
}

class_methods = {
    'NSXPCListener': {
        'serviceListener': 'NSXPCListener',
    },
    'NSXPCInterface': {
        'interfaceWithProtocol:': 'NSXPCInterface'
    },
    'NSFileManager': {
        'defaultManager': 'NSFileManager'
    }
}

objc_cls_alloc = [
    '_objc_alloc',
    '_objc_alloc_init',
    '_objc_allocWithZone',
    '_objc_opt_new',
]

objc_ret_as_is = [
    '_objc_autorelease',
    '_objc_retain',
    '_objc_retainAutorelease',

    # todo: handle return value
    '_objc_retainAutoreleaseReturnValue',
    '_objc_retainAutoreleasedReturnValue',
    '_objc_unsafeClaimAutoreleasedReturnValue',
]

objc_weak_mov = [
    '_objc_copyWeak',
    '_objc_moveWeak',
    # Treat the following two as mov
    '_objc_initWeak',
    '_objc_storeWeak',
    '_objc_initWeakOrNil',
    '_objc_storeWeakOrNil'
]

objc_weak_ret = [
    '_objc_loadWeakRetained',
    '_objc_loadWeak'
]

objc_strong_mov = [
    '_objc_storeStrong'
]

def arr2set(arr):
    s = set(map(symbol, arr))
    if idc.BADADDR in s:
        s.remove(idc.BADADDR)
    return s


allocators = arr2set(objc_cls_alloc)
arc = arr2set(objc_ret_as_is)

dispatchers = arr2set([
    '_dispatch_sync',
    '_dispatch_async',
])

nullability_annotations = [
    'nonnull',
    'nullable',
    '__nonnull',
    '__nullable',
    '_Nonnull',
    '_Nullable'
]

authentications = [
    'processIdentifier',
    'xpc_connection_get_pid',
    'auditToken',
    'xpc_connection_get_audit_token',
    'effectiveUserIdentifier',
    'effectiveGroupIdentifier',
    'auditSessionIdentifier',
    'kSecGuestAttributeAudit',
    'valueForEntitlement',
    'xpc_connection_copy_entitlement_value',
    'audit_token',
    'entitlement',
    'copyEntitlementsForPid'
]