"""Integration tests for the Flask REST API."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import tempfile
import json

tmp = tempfile.mktemp(suffix='.db')
import db.database as dbmod
dbmod.DB_PATH = tmp

from db.database import init_db
from core.rules import seed_default_rules
from web.app import create_app

init_db()
seed_default_rules()
app = create_app()
client = app.test_client()


def test_get_rules():
    res = client.get('/api/rules')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert isinstance(data, list)
    assert len(data) > 0  # default rules seeded
    print(f"PASS: test_get_rules ({len(data)} rules)")


def test_create_rule():
    payload = {
        'name': 'Test API Rule', 'description': 'Created by test',
        'action': 'block', 'protocol': 'tcp', 'direction': 'inbound',
        'dst_port': '8080', 'priority': 100,
    }
    res = client.post('/api/rules', data=json.dumps(payload),
                      content_type='application/json')
    assert res.status_code == 201
    data = json.loads(res.data)
    assert 'id' in data
    print(f"PASS: test_create_rule (id={data['id']})")
    return data['id']


def test_update_rule():
    # Create one first
    payload = {
        'name': 'Update Me', 'action': 'allow', 'protocol': 'udp',
        'direction': 'both', 'priority': 150,
    }
    res = client.post('/api/rules', data=json.dumps(payload),
                      content_type='application/json')
    rule_id = json.loads(res.data)['id']

    update = {'name': 'Updated Name', 'action': 'block', 'protocol': 'udp',
              'direction': 'both', 'priority': 150}
    res2 = client.put(f'/api/rules/{rule_id}', data=json.dumps(update),
                      content_type='application/json')
    assert res2.status_code == 200

    res3 = client.get('/api/rules')
    rules = json.loads(res3.data)
    updated = next((r for r in rules if r['id'] == rule_id), None)
    assert updated['name'] == 'Updated Name'
    print("PASS: test_update_rule")


def test_toggle_rule():
    res = client.get('/api/rules')
    rules = json.loads(res.data)
    non_default = next((r for r in rules if not r['is_default']), None)
    assert non_default is not None
    original = non_default['enabled']

    res2 = client.post(f"/api/rules/{non_default['id']}/toggle")
    assert res2.status_code == 200
    data = json.loads(res2.data)
    assert data['enabled'] != bool(original)
    print("PASS: test_toggle_rule")


def test_delete_default_rule_forbidden():
    res = client.get('/api/rules')
    rules = json.loads(res.data)
    default_rule = next((r for r in rules if r['is_default']), None)
    assert default_rule is not None
    res2 = client.delete(f"/api/rules/{default_rule['id']}")
    assert res2.status_code == 403
    print("PASS: test_delete_default_rule_forbidden")


def test_blacklist_add_and_list():
    payload = {'ip_address': '192.168.99.1', 'reason': 'API test'}
    res = client.post('/api/blacklist', data=json.dumps(payload),
                      content_type='application/json')
    assert res.status_code == 201

    res2 = client.get('/api/blacklist')
    data = json.loads(res2.data)
    ips = [e['ip_address'] for e in data]
    assert '192.168.99.1' in ips
    print("PASS: test_blacklist_add_and_list")


def test_blacklist_invalid_ip():
    payload = {'ip_address': 'not-an-ip', 'reason': 'bad'}
    res = client.post('/api/blacklist', data=json.dumps(payload),
                      content_type='application/json')
    assert res.status_code == 400
    print("PASS: test_blacklist_invalid_ip")


def test_stats_endpoint():
    res = client.get('/api/stats')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert 'total' in data
    assert 'blocked' in data
    assert 'allowed' in data
    print("PASS: test_stats_endpoint")


def test_logs_endpoint():
    res = client.get('/api/logs?limit=10')
    assert res.status_code == 200
    data = json.loads(res.data)
    assert isinstance(data, list)
    print("PASS: test_logs_endpoint")


def test_settings_get_and_set():
    res = client.get('/api/settings')
    assert res.status_code == 200
    settings = json.loads(res.data)
    assert 'engine_enabled' in settings

    res2 = client.post('/api/settings',
                       data=json.dumps({'engine_enabled': '0'}),
                       content_type='application/json')
    assert res2.status_code == 200

    res3 = client.get('/api/settings')
    s2 = json.loads(res3.data)
    assert s2['engine_enabled'] == '0'

    # Restore
    client.post('/api/settings', data=json.dumps({'engine_enabled': '1'}),
                content_type='application/json')
    print("PASS: test_settings_get_and_set")


def teardown():
    try:
        os.remove(tmp)
    except Exception:
        pass


if __name__ == '__main__':
    tests = [
        test_get_rules, test_create_rule, test_update_rule,
        test_toggle_rule, test_delete_default_rule_forbidden,
        test_blacklist_add_and_list, test_blacklist_invalid_ip,
        test_stats_endpoint, test_logs_endpoint, test_settings_get_and_set,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            import traceback
            print(f"FAIL: {t.__name__} — {e}")
            traceback.print_exc()
            failed += 1
    teardown()
    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
