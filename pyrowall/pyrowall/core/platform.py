"""Platform detection and OS adapter selector."""

import platform
import logging

log = logging.getLogger('pyrowall.platform')

_system = platform.system()


def get_adapter():
    if _system == 'Linux':
        from adapters.linux_iptables import apply_rule, block_ip, unblock_ip, flush_pyrowall_rules
    elif _system == 'Windows':
        from adapters.windows_wfp import apply_rule, block_ip, unblock_ip, flush_pyrowall_rules
    else:
        log.warning(f"Unsupported platform: {_system}. OS-level rules will not be applied.")
        def apply_rule(r): pass
        def block_ip(ip): pass
        def unblock_ip(ip): pass
        def flush_pyrowall_rules(): pass

    return {
        'apply_rule': apply_rule,
        'block_ip': block_ip,
        'unblock_ip': unblock_ip,
        'flush': flush_pyrowall_rules,
    }


def is_linux():
    return _system == 'Linux'


def is_windows():
    return _system == 'Windows'
