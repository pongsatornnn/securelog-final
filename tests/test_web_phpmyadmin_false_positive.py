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

    def test_missing_token_or_signature_and_other_endpoint_are_not_exempt(self):
        unsigned = phpmyadmin_path().replace(f"&sql_signature={SQL_SIGNATURE}", "")
        no_token = phpmyadmin_path().replace(f"&token={TOKEN}", "")
        other = phpmyadmin_path().replace("/phpmyadmin/index.php", "/search")
        for path in (unsigned, no_token, other):
            with self.subTest(path=path):
                self.assertIn("sql_injection", detection_types(path))

    def test_duplicate_sql_query_is_not_exempt(self):
        self.assertIn("sql_injection", detection_types(phpmyadmin_path(extra="&sql_query=SELECT+1")))

    def test_malformed_route_or_token_is_not_exempt(self):
        bad_route = phpmyadmin_path(route="/login")
        bad_token = phpmyadmin_path().replace(TOKEN, "invalid")
        self.assertIn("sql_injection", detection_types(bad_route))
        self.assertIn("sql_injection", detection_types(bad_token))


if __name__ == "__main__":
    unittest.main()
