"""Windows firewall adapter using netsh advfirewall."""

import subprocess
import logging

log = logging.getLogger('akid_firewall.windows')


def run(cmd):
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True
        )
        if result.returncode != 0:
            log.warning(f"netsh: {result.stderr.strip()}")
        return result.returncode == 0
    except Exception as e:
        log.error(f"netsh error: {e}")
        return False


def apply_rule(rule):
    """Translate an AKID Firewall rule to netsh advfirewall rule."""
    rule_name = f"AKID_FW_{rule['id']}_{rule['name'].replace(' ', '_')}"
    action = 'block' if rule['action'] == 'block' else 'allow'

    dir_map = {'inbound': 'in', 'outbound': 'out', 'both': None}
    directions = ['in', 'out'] if rule.get('direction') == 'both' else [dir_map.get(rule.get('direction', 'both'), 'in')]

    for direction in directions:
        parts = [
            'netsh advfirewall firewall add rule',
            f'name="{rule_name}_{direction}"',
            f'dir={direction}',
            f'action={action}',
        ]

        proto = rule.get('protocol', 'any')
        if proto and proto != 'any':
            parts.append(f'protocol={proto}')

        dst_port = rule.get('dst_port', 'any')
        if dst_port and dst_port != 'any' and proto in ('tcp', 'udp'):
            parts.append(f'localport={dst_port}')

        src_ip = rule.get('src_ip', 'any')
        if src_ip and src_ip != 'any':
            parts.append(f'remoteip={src_ip}')

        run(' '.join(parts))


def block_ip(ip):
    run(f'netsh advfirewall firewall add rule name="AKID_FW_Block_{ip}" dir=in action=block remoteip={ip}')
    run(f'netsh advfirewall firewall add rule name="AKID_FW_Block_{ip}_out" dir=out action=block remoteip={ip}')


def unblock_ip(ip):
    run(f'netsh advfirewall firewall delete rule name="AKID_FW_Block_{ip}"')
    run(f'netsh advfirewall firewall delete rule name="AKID_FW_Block_{ip}_out"')


def flush_firewall_rules():
    run('netsh advfirewall firewall delete rule name="AKID_FW*"')
