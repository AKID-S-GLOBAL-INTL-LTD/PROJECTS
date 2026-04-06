"""Tests for RuleModel and BlacklistModel database operations."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Use a temp DB for testing
import tempfile
tmp = tempfile.mktemp(suffix='.db')
import db.database as dbmod
dbmod.DB_PATH = tmp

from db.database import init_db
from db.models import RuleModel, BlacklistModel


def setup():
    init_db()
    print("Test DB initialized at", tmp)


def test_create_and_list_rule():
    rule = {
        'name':'Test Rule','description':'desc','action':'block',
        'protocol':'tcp','direction':'both','src_ip':'any','dst_ip':'any',
        'src_port':'any','dst_port':'80','is_default':0,'enabled':1,'priority':50,
    }
    rule_id = RuleModel.create(rule)
    assert rule_id > 0
    rules = RuleModel.all()
    found = next((r for r in rules if r['id'] == rule_id), None)
    assert found is not None
    assert found['name'] == 'Test Rule'
    print("PASS: test_create_and_list_rule")


def test_toggle_rule():
    rule = {
        'name':'Toggle Test','description':'','action':'allow',
        'protocol':'udp','direction':'inbound','src_ip':'any','dst_ip':'any',
        'src_port':'any','dst_port':'53','is_default':0,'enabled':1,'priority':60,
    }
    rule_id = RuleModel.create(rule)
    RuleModel.toggle(rule_id)
    updated = RuleModel.get(rule_id)
    assert updated['enabled'] == 0
    RuleModel.toggle(rule_id)
    updated2 = RuleModel.get(rule_id)
    assert updated2['enabled'] == 1
    print("PASS: test_toggle_rule")


def test_delete_non_default_rule():
    rule = {
        'name':'To Delete','description':'','action':'block',
        'protocol':'any','direction':'both','src_ip':'any','dst_ip':'any',
        'src_port':'any','dst_port':'any','is_default':0,'enabled':1,'priority':99,
    }
    rule_id = RuleModel.create(rule)
    RuleModel.delete(rule_id)
    assert RuleModel.get(rule_id) is None
    print("PASS: test_delete_non_default_rule")


def test_blacklist_add_and_contains():
    BlacklistModel.add('1.2.3.4', 'test')
    assert BlacklistModel.contains('1.2.3.4')
    assert not BlacklistModel.contains('9.9.9.9')
    print("PASS: test_blacklist_add_and_contains")


def test_blacklist_remove():
    BlacklistModel.add('5.5.5.5', 'remove test')
    entries = BlacklistModel.all()
    entry = next((e for e in entries if e['ip_address'] == '5.5.5.5'), None)
    assert entry is not None
    BlacklistModel.remove_by_id(entry['id'])
    assert not BlacklistModel.contains('5.5.5.5')
    print("PASS: test_blacklist_remove")


def test_no_duplicate_blacklist():
    BlacklistModel.add('7.7.7.7', 'first')
    BlacklistModel.add('7.7.7.7', 'duplicate')
    entries = [e for e in BlacklistModel.all() if e['ip_address'] == '7.7.7.7']
    assert len(entries) == 1
    print("PASS: test_no_duplicate_blacklist")


def teardown():
    try:
        os.remove(tmp)
    except Exception:
        pass


if __name__ == '__main__':
    setup()
    tests = [
        test_create_and_list_rule,
        test_toggle_rule,
        test_delete_non_default_rule,
        test_blacklist_add_and_contains,
        test_blacklist_remove,
        test_no_duplicate_blacklist,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"FAIL: {t.__name__} — {e}")
            failed += 1
    teardown()
    print(f"\n{'='*40}")
    print(f"Results: {passed} passed, {failed} failed")
