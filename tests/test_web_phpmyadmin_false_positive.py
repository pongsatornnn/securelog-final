import unittest
from urllib.parse import quote_plus

from process_log_detect.normalize_log import normalize_web
from process_log_detect import web_log_detect
from signature_cache import DEFAULT_SIGNATURES


SQL_SIGNATURE = "a" * 64
WHERE_SIGNATURE = "b" * 64
TOKEN = "c" * 32


def phpmyadmin_path(week: int = 9, *, sql_query: str = "SELECT * FROM `weekly_deadlines`",
                    route: str = "/table/change", extra: str = "") -> str:
    return (
        f"/phpmyadmin/index.php?route={route}&db=coop&table=weekly_deadlines"
        f"&where_clause={quote_plus(f'`weekly_deadlines`.`week_no` = \'Week {week}\'')}"
        f"&where_clause_signature={WHERE_SIGNATURE}"
        f"&sql_query={quote_plus(sql_query)}&sql_signature={SQL_SIGNATURE}"
        f"&token={TOKEN}{extra}"
    )


def detection_types(path: str) -> list[str]:
    message = (
        "198.51.100.20 - - [20/Oct/2026:20:45:30 +0700] "
        f'"GET {path} HTTP/1.1" 200 7719 "-" "Mozilla/5.0"'
    )
    normalized = normalize_web({"message": message, "log_type": "apache_access"})
    return [kind for kind, _ in web_log_detect.detect_attack_types(
        web_log_detect.build_haystack(normalized),
        web_log_detect.build_haystack(normalized, mask_phpmyadmin_sql=True),
        web_log_detect.build_haystack(normalized, mask_phpmyadmin_command=True),
        web_log_detect.build_haystack(normalized, split_query_parameters=True),
    )]


class PhpMyAdminFalsePositiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.previous = web_log_detect._compiled_signatures.copy()
        web_log_detect._compiled_signatures.clear()
        web_log_detect._compiled_signatures.update({
            kind: web_log_detect.compile_patterns(patterns)
            for kind, patterns in DEFAULT_SIGNATURES.items()
        })

    @classmethod
    def tearDownClass(cls):
        web_log_detect._compiled_signatures.clear()
        web_log_detect._compiled_signatures.update(cls.previous)

    def test_normal_table_navigation_does_not_match_sqli(self):
        for week in range(9, 14):
            with self.subTest(week=week):
                self.assertNotIn("sql_injection", detection_types(phpmyadmin_path(week)))

    def test_signed_week_links_with_ajax_do_not_match_xss(self):
        for week in range(5, 8):
            path = phpmyadmin_path(week, extra=(
                "&clause_is_unique=1&goto=index.php%3Froute%3D%2Fsql"
                "&default_action=update&ajax_request=true&ajax_page_request=true"
                "&_nocache=179248623252672787"
            ))
            with self.subTest(week=week):
                self.assertEqual([], detection_types(path))

    def test_xss_within_single_parameter_remains_detected(self):
        path = phpmyadmin_path(extra="&note=%27%3E%3Csvg%20onload%3Dalert(1)%3E")
        self.assertIn("xss", detection_types(path))

    def test_complex_sql_and_other_routes_do_not_match_sqli(self):
        for route, sql_query in (
            ("/table/change", "UPDATE `weekly_deadlines` SET title=NOW() WHERE week_no IN ('9', '10')"),
            ("/sql", "SELECT a.week_no FROM `weekly_deadlines` a JOIN `users` u ON a.user_id=u.id"),
            ("/database/sql", "SELECT * FROM `weekly_deadlines` UNION SELECT * FROM `archive`"),
        ):
            with self.subTest(route=route, sql_query=sql_query):
                self.assertNotIn("sql_injection", detection_types(phpmyadmin_path(
                    route=route, sql_query=sql_query,
                )))

    def test_normal_signed_database_operations_are_not_attacks(self):
        queries = (
            "SELECT * FROM `products` WHERE `name` = 'A&B'",
            "INSERT INTO `products` (`name`, `price`) VALUES ('Mouse', 12.50)",
            "UPDATE `products` SET `name` = 'Mouse Pro' WHERE `id` = 2",
            "DELETE FROM `products` WHERE `id` = 2",
            "CREATE TABLE `notes` (`id` INT PRIMARY KEY, `note` TEXT)",
            "SELECT * FROM `products` ORDER BY `price` DESC",
        )
        for query in queries:
            path = (
                "/phpmyadmin/index.php?route=/sql&db=coop&table=products"
                f"&sql_query={quote_plus(query)}&sql_signature={SQL_SIGNATURE}"
                f"&token={TOKEN}"
            )
            with self.subTest(query=query):
                self.assertEqual([], detection_types(path))

    def test_signed_where_clause_is_covered(self):
        path = phpmyadmin_path().replace(
            "where_clause=", "where_clause=SELECT+1+FROM+`weekly_deadlines`+AND+",
        )
        self.assertNotIn("sql_injection", detection_types(path))

    def test_other_attack_types_still_scan_sql_query(self):
        path = phpmyadmin_path(sql_query=(
            "UPDATE `weekly_deadlines` SET `title` = 'alert(1)' WHERE `week_no` = 'Week 9'"
        ))
        self.assertIn("xss", detection_types(path))

    def test_other_parameters_still_scan_for_sql_injection(self):
        path = phpmyadmin_path(extra="&filter=%2527%2BOR%2B1%253D1")
        self.assertIn("sql_injection", detection_types(path))

    def test_sort_links_without_token_are_not_attacks(self):
        path = (
            "/phpmyadmin/index.php?route=/sql&db=coop&table=weekly_deadlines"
            "&sql_query=SELECT+%2A+FROM+%60weekly_deadlines%60++%0A"
            "ORDER+BY+%60weekly_deadlines%60.%60week_no%60+ASC"
            f"&sql_signature={SQL_SIGNATURE}&session_max_rows=25"
        )
        self.assertNotIn("sql_injection", detection_types(path))
        self.assertNotIn("command_injection", detection_types(path))

    def test_system_database_navigation_is_not_sql_injection(self):
        path = "/phpmyadmin/index.php?route=/database/structure&db=information_schema"
        self.assertNotIn("sql_injection", detection_types(path))

    def test_other_phpmyadmin_navigation_links_are_not_attacks(self):
        paths = (
            "/phpmyadmin/index.php?route=/server/databases&statistics=0&pos=0"
            "&sort_by=SCHEMA_NAME&sort_order=desc",
            "/phpmyadmin/index.php?route=/server/privileges"
            "&db=information_schema&checkprivsdb=information_schema",
            "/phpmyadmin/index.php?route=/database/data-dictionary&db=coop"
            "&goto=index.php%3Froute%3D%2Fdatabase%2Fstructure",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual([], detection_types(path))

    def test_unusual_navigation_values_remain_visible(self):
        paths = (
            "/phpmyadmin/index.php?route=/server/databases&sort_by=SCHEMA_NAME%3Bid",
            "/phpmyadmin/index.php?route=/server/privileges"
            "&checkprivsdb=information_schema%27+OR+1%3D1--+",
            "/phpmyadmin/index.php?route=/database/data-dictionary"
            "&goto=index.php%3Froute%3D%2Fdatabase%2Fstructure%3Bid",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(detection_types(path))

    def test_sql_identifier_backticks_are_not_shell_commands(self):
        path = phpmyadmin_path().replace(f"&token={TOKEN}", "")
        self.assertNotIn("command_injection", detection_types(path))

    def test_missing_signature_and_other_endpoint_are_not_exempt(self):
        unsigned = phpmyadmin_path().replace(f"&sql_signature={SQL_SIGNATURE}", "")
        other = phpmyadmin_path().replace("/phpmyadmin/index.php", "/search")
        for path in (unsigned, other):
            with self.subTest(path=path):
                self.assertIn("sql_injection", detection_types(path))

    def test_unsigned_row_edit_link_from_phpmyadmin(self):
        path = (
            "/phpmyadmin/index.php?route=/table/change&db=coop&table=products"
            "&where_clause=%60products%60.%60id%60+%3D+2&clause_is_unique=1"
            "&sql_query=SELECT+%2A+FROM+%60products%60&default_action=update"
        )
        self.assertNotIn("sql_injection", detection_types(path))
        self.assertNotIn("command_injection", detection_types(path))
        self.assertIn("sql_injection", detection_types(path.replace("+2&", "+2+OR+1%3D1&")))
        self.assertIn("sql_injection", detection_types(path.replace("clause_is_unique=1", "clause_is_unique=0")))

    def test_sorted_row_edit_link_from_phpmyadmin(self):
        path = (
            "/phpmyadmin/index.php?route=/table/change&db=coop&table=products"
            "&where_clause=%60products%60.%60id%60+%3D+2&clause_is_unique=1"
            "&sql_query=SELECT+%2A+FROM+%60products%60++%0A"
            "ORDER+BY+%60products%60.%60notes%60+ASC&default_action=update"
        )
        self.assertNotIn("sql_injection", detection_types(path))
        self.assertNotIn("command_injection", detection_types(path))
        self.assertIn("sql_injection", detection_types(path.replace(
            "+ASC&", "+ASC+UNION+SELECT+password+FROM+users&",
        )))

    def test_command_payload_in_other_parameter_is_still_detected(self):
        path = phpmyadmin_path(extra="&filter=%3Bid")
        self.assertIn("command_injection", detection_types(path))

    def test_duplicate_sql_query_is_not_exempt(self):
        self.assertIn("sql_injection", detection_types(phpmyadmin_path(extra="&sql_query=SELECT+1")))

    def test_malformed_route_or_token_is_not_exempt(self):
        bad_route = phpmyadmin_path(route="/login")
        bad_token = phpmyadmin_path().replace(TOKEN, "invalid")
        self.assertIn("sql_injection", detection_types(bad_route))
        self.assertIn("sql_injection", detection_types(bad_token))


if __name__ == "__main__":
    unittest.main()
