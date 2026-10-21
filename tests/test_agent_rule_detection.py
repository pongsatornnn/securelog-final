import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from process_log_detect import web_log_detect
from routes import rules as rule_routes
import rule_cache
from schemas.rule_schema import UpdateAgentRulesRequest
from fastapi import HTTPException


class AgentRuleCacheTests(unittest.IsolatedAsyncioTestCase):
    async def test_rule_disabled_for_one_agent_only(self):
        cached = {
            "detection_rule:web_sql_injection": {
                "rule_key": "web_sql_injection", "window_seconds": 300,
                "threshold": 1, "is_active": True,
            },
            "agent_disabled_rules:Agent_001": {"disabled": ["web_sql_injection"]},
            "agent_disabled_rules:Agent_002": {"disabled": []},
        }
        with patch.object(rule_cache, "cache_get_json", side_effect=lambda key, **_: cached.get(key)):
            one = await rule_cache.get_rule("web_sql_injection", "Agent_001")
            two = await rule_cache.get_rule("web_sql_injection", "Agent_002")

        self.assertFalse(one["is_active"])
        self.assertTrue(two["is_active"])
        self.assertTrue(cached["detection_rule:web_sql_injection"]["is_active"])


class AgentRuleApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_rejects_unknown_and_dashboard_login_rules(self):
        rules = [
            SimpleNamespace(rule_key="web_sql_injection", category="web"),
            SimpleNamespace(rule_key="login_lockout", category="login"),
        ]
        with (
            patch.object(rule_routes, "get_agent_by_agent_id", AsyncMock(return_value=object())),
            patch.object(rule_routes, "get_all_detection_rules", AsyncMock(return_value=rules)),
            patch.object(rule_routes, "set_agent_disabled_rules", AsyncMock()) as save,
        ):
            for key in ("login_lockout", "unknown_rule"):
                with self.subTest(key=key), self.assertRaises(HTTPException) as raised:
                    await rule_routes.api_update_agent_rule_settings(
                        "Agent_001", UpdateAgentRulesRequest(disabled_rules=[key]),
                        user=object(), db=object(),
                    )
                self.assertEqual(raised.exception.status_code, 400)
            save.assert_not_awaited()

    async def test_saves_and_invalidates_agent_cache(self):
        rules = [SimpleNamespace(rule_key="web_sql_injection", category="web")]
        with (
            patch.object(rule_routes, "get_agent_by_agent_id", AsyncMock(return_value=object())),
            patch.object(rule_routes, "get_all_detection_rules", AsyncMock(return_value=rules)),
            patch.object(rule_routes, "set_agent_disabled_rules", AsyncMock()) as save,
            patch.object(rule_routes, "clear_agent_rule_cache", Mock()) as clear,
        ):
            result = await rule_routes.api_update_agent_rule_settings(
                "Agent_001",
                UpdateAgentRulesRequest(disabled_rules=["web_sql_injection"]),
                user=object(), db=object(),
            )
        self.assertEqual(result["disabled_rules"], ["web_sql_injection"])
        save.assert_awaited_once()
        clear.assert_called_once_with("Agent_001")


class AgentWebDetectionTests(unittest.TestCase):
    def setUp(self):
        web_log_detect.events_by_key.clear()
        self.loop = asyncio.new_event_loop()

    def tearDown(self):
        self.loop.close()
        web_log_detect.events_by_key.clear()

    def test_disabled_sql_falls_through_to_xss_and_agents_do_not_share_count(self):
        saved = []

        async def get_rule(rule_key, agent_id=None):
            return {
                "is_active": not (agent_id == "Agent_001" and rule_key == "web_sql_injection"),
                "window_seconds": 300,
                "threshold": 2,
            }

        async def save_alert_to_db(**kwargs):
            saved.append((kwargs["agent_id"], kwargs["detection_type"]))

        def log(agent_id):
            return {"category": "web", "agent_id": agent_id, "source_ip": "198.51.100.1"}

        matches = [("sql_injection", "sql"), ("xss", "xss")]
        with (
            patch.object(web_log_detect, "get_rule", get_rule),
            patch.object(web_log_detect, "reload_signatures"),
            patch.object(web_log_detect, "process_http_flood"),
            patch.object(web_log_detect, "parse_agent_time_to_epoch", return_value=1000),
            patch.object(web_log_detect, "build_haystack", return_value=[]),
            patch.object(web_log_detect, "detect_attack_types", return_value=matches),
            patch.object(web_log_detect, "print_counted_web_log"),
            patch.object(web_log_detect, "print_web_alert"),
            patch.object(web_log_detect, "save_alert_to_db", save_alert_to_db),
        ):
            web_log_detect.process_web_log(log("Agent_001"), self.loop)
            web_log_detect.process_web_log(log("Agent_002"), self.loop)
            self.assertEqual(saved, [])
            web_log_detect.process_web_log(log("Agent_001"), self.loop)
            web_log_detect.process_web_log(log("Agent_002"), self.loop)

        self.assertEqual(saved, [
            ("Agent_001", "xss"),
            ("Agent_002", "sql_injection"),
        ])


if __name__ == "__main__":
    unittest.main()
