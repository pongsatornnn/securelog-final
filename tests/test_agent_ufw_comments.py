import ast
import subprocess
import unittest
from pathlib import Path
from unittest.mock import Mock


AGENT_SOURCE = Path(__file__).resolve().parents[1] / "for_Agent/package/agent_core.py"
FUNCTIONS = {
    "ufw_block_comment", "is_our_ufw_comment", "ufw_deny_rule_owner",
    "_ufw_block", "_ufw_unblock", "block_ip", "unblock_ip",
    "sync_block_ip", "sync_blacklist_desired_state", "extract_ip",
    "normalize_ip_list",
}


def load_firewall_functions():
    source = ast.parse(AGENT_SOURCE.read_text(encoding="utf-8"))
    definitions = [
        node for node in source.body
        if (isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS)
        or (isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "ATTACK_COMMENT_LABELS"
            for target in node.targets
        ))
    ]
    module = ast.fix_missing_locations(ast.Module(body=definitions, type_ignores=[]))
    namespace = {
        "subprocess": subprocess,
        "UFW_COMMENT": "central_blacklist",
        "is_never_block": lambda ip: False,
        "drop_conntrack": Mock(),
        "load_managed_ips": lambda: set(),
        "save_managed_ips": Mock(),
    }
    exec(compile(module, str(AGENT_SOURCE), "exec"), namespace)
    return namespace


class AgentUfwCommentsTests(unittest.TestCase):
    def setUp(self):
        self.agent = load_firewall_functions()
        self.commands = []
        self.status = "Status: active\n"
        self.status_code = 0
        self.old_run = subprocess.run

        def fake_run(command, **kwargs):
            self.commands.append(command)
            if command == ["sudo", "ufw", "status"]:
                return subprocess.CompletedProcess(command, self.status_code, self.status, "")
            return subprocess.CompletedProcess(command, 0, "", "")

        subprocess.run = fake_run

    def tearDown(self):
        subprocess.run = self.old_run

    def test_new_rule_has_attack_type(self):
        self.assertTrue(self.agent["block_ip"]("198.51.100.5", "sql_injection"))
        self.assertEqual(self.commands[-1][-2:], ["comment", "central_blacklist: SQL Injection"])

    def test_each_attack_type_has_its_own_label(self):
        expected = {
            "ssh_brute_force": "SSH Brute Force",
            "sudo_failed": "Sudo Authentication Failure",
            "sql_injection": "SQL Injection",
            "xss": "Cross-Site Scripting (XSS)",
            "path_traversal": "Path Traversal",
            "command_injection": "Command Injection",
            "http_flood": "HTTP Flood",
            "firewall_deny_rate": "Firewall Deny Flood",
            "port_scan": "Port Scan",
            "manual_blacklist": "Manual Blacklist",
        }
        for event, label in expected.items():
            with self.subTest(event=event):
                self.assertEqual(self.agent["ufw_block_comment"](event), f"central_blacklist: {label}")

    def test_existing_foreign_rule_is_never_changed_even_if_state_says_managed(self):
        self.agent["load_managed_ips"] = lambda: {"198.51.100.5"}
        self.status += "Anywhere  DENY IN  198.51.100.5  # admin rule\n"
        self.assertFalse(self.agent["block_ip"]("198.51.100.5", "web_xss"))
        self.assertFalse(self.agent["unblock_ip"]("198.51.100.5"))
        self.assertEqual(self.commands, [["sudo", "ufw", "status"]] * 2)

    def test_existing_admin_allow_is_respected(self):
        self.status += "Anywhere  ALLOW IN  198.51.100.5  # admin exception\n"
        self.assertFalse(self.agent["block_ip"]("198.51.100.5", "web_xss"))
        self.assertEqual(self.commands, [["sudo", "ufw", "status"]])

    def test_old_and_new_owned_comments_are_recognized_without_duplicate(self):
        for comment in ("central_blacklist", "central_blacklist: web_xss"):
            with self.subTest(comment=comment):
                self.commands.clear()
                self.status = f"Status: active\nAnywhere  DENY IN  198.51.100.5  # {comment}\n"
                self.assertTrue(self.agent["block_ip"]("198.51.100.5", "web_sql_injection"))
                self.assertEqual(self.commands, [["sudo", "ufw", "status"]])

    def test_owned_rule_can_still_be_unblocked(self):
        self.status += "Anywhere  DENY IN  198.51.100.5  # central_blacklist: web_xss\n"
        self.assertTrue(self.agent["unblock_ip"]("198.51.100.5"))
        self.assertEqual(self.commands[-1], ["sudo", "ufw", "delete", "deny", "from", "198.51.100.5", "to", "any"])

    def test_untrusted_event_cannot_change_comment_format(self):
        self.assertEqual(self.agent["ufw_block_comment"]("web_xss\nextra"), "central_blacklist: Unspecified")

    def test_mixed_owned_and_foreign_rules_do_not_trigger_delete(self):
        self.status += "Anywhere  DENY IN  198.51.100.5  # central_blacklist: web_xss\n"
        self.status += "Anywhere  DENY IN  198.51.100.5  # admin rule\n"
        self.assertFalse(self.agent["unblock_ip"]("198.51.100.5"))
        self.assertEqual(self.commands, [["sudo", "ufw", "status"]])

    def test_ipv6_owned_rule_is_recognized(self):
        self.status += "Anywhere (v6)  DENY IN  2001:db8::5 (v6)  # central_blacklist: web_xss\n"
        self.assertEqual(self.agent["ufw_deny_rule_owner"]("2001:db8::5"), "ours")

    def test_unreadable_status_never_changes_rules(self):
        self.status_code = 1
        self.assertFalse(self.agent["block_ip"]("198.51.100.5", "web_xss"))
        self.assertFalse(self.agent["unblock_ip"]("198.51.100.5"))
        self.assertEqual(self.commands, [["sudo", "ufw", "status"]] * 2)

    def test_sync_forwards_event_from_central(self):
        received = []
        self.agent["sync_block_ip"] = lambda ip, event: received.append((ip, event)) or True
        self.agent["sync_unblock_ip"] = lambda ip: True
        self.agent["sync_blacklist_desired_state"]([
            {"ip_address": "198.51.100.5", "event": "firewall_port_scan"},
        ])
        self.assertEqual(received, [("198.51.100.5", "firewall_port_scan")])
        self.agent["save_managed_ips"].assert_called_once_with({"198.51.100.5"})


if __name__ == "__main__":
    unittest.main()
