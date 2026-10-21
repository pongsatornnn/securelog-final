import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "for_Agent/package/uninstall.sh"
source = SCRIPT.read_text(encoding="utf-8")
FIREWALL_FUNCTION = source.split("remove_securelog_rules() {", 1)[1].split(
    "# ---------- อ่าน flag ----------", 1
)[0]
FIREWALL_FUNCTION = "remove_securelog_rules() {" + FIREWALL_FUNCTION


class ClientUninstallRulesTests(unittest.TestCase):
    def run_cleanup(self, status, *, fail_status=False, fail_delete=""):
        with tempfile.TemporaryDirectory() as directory:
            deleted = Path(directory) / "deleted.txt"
            env = {**os.environ, "UFW_STATUS": status, "DELETED_FILE": str(deleted)}
            env["FAIL_STATUS"] = "1" if fail_status else "0"
            env["FAIL_DELETE"] = fail_delete
            script = """
set -euo pipefail
log() { :; }
die() { echo "$*" >&2; exit 1; }
ufw() {
    if [ "$1" = status ]; then
        [ "$FAIL_STATUS" = 0 ] || return 1
        printf '%s\\n' "$UFW_STATUS"
    else
        [ "$3" != "$FAIL_DELETE" ] || return 1
        printf '%s\\n' "$3" >> "$DELETED_FILE"
    fi
}
""" + FIREWALL_FUNCTION + "\nremove_securelog_rules\n"
            result = subprocess.run(
                ["bash", "-c", script], env=env, capture_output=True, text=True
            )
            numbers = deleted.read_text().splitlines() if deleted.exists() else []
            return result, numbers

    def test_removes_only_tagged_rules_by_number_in_reverse_order(self):
        status = """Status: active
[ 1] 22/tcp       ALLOW IN    Anywhere       # admin SSH
[ 2] Anywhere     DENY IN     198.51.100.2  # Securelog:SQL Injection
[ 3] Anywhere     DENY IN     198.51.100.3  # admin block
[ 4] 6380/tcp     ALLOW OUT   Anywhere       # SecureLog agent -> central Redis
[ 5] Anywhere     DENY IN     198.51.100.5  # central_blacklist: web_xss
[ 6] Anywhere     ALLOW IN    198.51.100.6  # Securelog:admin exception
"""
        result, numbers = self.run_cleanup(status)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(numbers, ["5", "4", "2"])

    def test_cannot_read_status_stops_before_deleting(self):
        result, numbers = self.run_cleanup("", fail_status=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(numbers, [])

    def test_inactive_ufw_does_not_claim_to_remove_hidden_rules(self):
        result, numbers = self.run_cleanup("Status: inactive")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("inactive", result.stderr)
        self.assertEqual(numbers, [])

    def test_delete_failure_stops_uninstall(self):
        status = "[ 2] Anywhere DENY IN 198.51.100.2 # Securelog:SQL Injection"
        result, numbers = self.run_cleanup(status, fail_delete="2")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(numbers, [])


if __name__ == "__main__":
    unittest.main()
