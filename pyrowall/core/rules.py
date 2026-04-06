"""Rule management and default rule seeding."""

import logging
from db.models import RuleModel

log = logging.getLogger('akid_firewall.rules')

DEFAULT_RULES = [
    {
        'name':        'Block HTTP Traffic',
        'description': 'Block all unencrypted HTTP traffic on port 80',
        'action':      'block',
        'protocol':    'tcp',
        'direction':   'both',
        'src_ip':      'any',
        'dst_ip':      'any',
        'src_port':    'any',
        'dst_port':    '80',
        'is_default':  1,
        'enabled':     1,
        'priority':    10,
    },
    {
        'name':        'Block ICMP (Ping)',
        'description': 'Block all ICMP echo requests and replies',
        'action':      'block',
        'protocol':    'icmp',
        'direction':   'both',
        'src_ip':      'any',
        'dst_ip':      'any',
        'src_port':    'any',
        'dst_port':    'any',
        'is_default':  1,
        'enabled':     1,
        'priority':    11,
    },
    {
        'name':        'Allow HTTPS',
        'description': 'Allow encrypted HTTPS traffic on port 443',
        'action':      'allow',
        'protocol':    'tcp',
        'direction':   'both',
        'src_ip':      'any',
        'dst_ip':      'any',
        'src_port':    'any',
        'dst_port':    '443',
        'is_default':  1,
        'enabled':     1,
        'priority':    20,
    },
    {
        'name':        'Allow DNS',
        'description': 'Allow DNS resolution on UDP/TCP port 53',
        'action':      'allow',
        'protocol':    'udp',
        'direction':   'both',
        'src_ip':      'any',
        'dst_ip':      'any',
        'src_port':    'any',
        'dst_port':    '53',
        'is_default':  1,
        'enabled':     1,
        'priority':    21,
    },
    {
        'name':        'Allow Loopback',
        'description': 'Allow all traffic on loopback interface (127.x.x.x)',
        'action':      'allow',
        'protocol':    'any',
        'direction':   'both',
        'src_ip':      '127.0.0.0/8',
        'dst_ip':      'any',
        'src_port':    'any',
        'dst_port':    'any',
        'is_default':  1,
        'enabled':     1,
        'priority':    1,
    },
    {
        'name':        'Allow SSH',
        'description': 'Allow SSH connections on port 22',
        'action':      'allow',
        'protocol':    'tcp',
        'direction':   'inbound',
        'src_ip':      'any',
        'dst_ip':      'any',
        'src_port':    'any',
        'dst_port':    '22',
        'is_default':  1,
        'enabled':     1,
        'priority':    22,
    },
]


def seed_default_rules():
    """Insert default rules only if the table is empty."""
    existing = RuleModel.all()
    if existing:
        log.info(f"Rules already exist ({len(existing)} rules), skipping seed.")
        return

    log.info("Seeding default rules...")
    for rule in DEFAULT_RULES:
        RuleModel.create(rule)
    log.info(f"Seeded {len(DEFAULT_RULES)} default rules.")
