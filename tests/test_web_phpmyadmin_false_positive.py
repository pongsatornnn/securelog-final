import unittest
from urllib.parse import quote_plus

from process_log_detect.normalize_log import normalize_web
from process_log_detect import web_log_detect
from signature_cache import DEFAULT_SIGNATURES


SQL_SIGNATURE = "a" * 64
WHERE_SIGNATURE = "b" * 64


def phpmyadmin_path(week: int = 9, *, sql_query: str = "SELECT * FROM `weekly_deadlines`",
                    extra: str = "") -> str:
    return (
        "/phpmyadmin/index.php?route=/table/change&db=coop&table=weekly_deadlines"
        f"&where_clause={quote_plus(f'`weekly_deadlines`.`week_no` = \'Week {week}\'')}"
        f"&where_clause_signature={WHERE_SIGNATURE}"
        f"&sql_query={quote_plus(sql_query)}&sql_signature={SQL_SIGNATURE}"
        f"{extra}"
    )


def detection_types(path: str) -> list[str]:
    message = (
        "198.51.100.20 - - [20/Oct/2026:20:45:30 +0700] "
        f'"GET {path} HTTP/1.1" 200 7719 "-" "Mozilla/5.0"'
    )
    normalized = normalize_web({"message": message, "log_type": "apache_access"})
    return [kind for kind, _ in web_log_detect.detect_attack_types(
        web_log_detect.build_haystack(normalized)
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

    def test_attack_inside_sql_query_is_still_detected(self):
        path = phpmyadmin_path(sql_query="SELECT * FROM `weekly_deadlines` UNION SELECT password")
        self.assertIn("sql_injection", detection_types(path))

    def test_attack_in_another_parameter_is_still_detected(self):
        path = phpmyadmin_path(extra="&filter=%2527%2BOR%2B1%253D1")
        self.assertIn("sql_injection", detection_types(path))

    def test_unsigned_or_other_endpoint_is_still_detected(self):
        unsigned = phpmyadmin_path().replace(f"&sql_signature={SQL_SIGNATURE}", "")
        other = phpmyadmin_path().replace("/phpmyadmin/index.php", "/search")
        self.assertIn("sql_injection", detection_types(unsigned))
        self.assertIn("sql_injection", detection_types(other))

    def test_duplicate_query_is_not_suppressed(self):
        self.assertIn("sql_injection", detection_types(phpmyadmin_path(extra="&sql_query=SELECT+1")))


if __name__ == "__main__":
    unittest.main()
