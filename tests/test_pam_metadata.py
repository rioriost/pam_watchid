"""Check shell comparison failures without touching live PAM or filesystem metadata."""

from pathlib import Path
import subprocess
import unittest


PROJECT = Path(__file__).resolve().parents[1]


class MetadataComparisonTests(unittest.TestCase):
    def test_comparisons_check_command_status_before_using_output(self):
        manager = (PROJECT / "packaging/pam-config.sh").read_text(encoding="utf-8")
        cases = [
            ("same attributes",
             'pam_xattrs() { printf "same\\n"; }; pam_preserved_xattrs left right', 0),
            ("different attributes",
             'pam_xattrs() { printf "%s\\n" "$1"; }; pam_preserved_xattrs left right', 1),
            ("failed empty attributes",
             'pam_xattrs() { return 1; }; '
             'if pam_preserved_xattrs left right; then exit 0; else exit 99; fi', 1),
            ("failed partial attributes",
             'pam_xattrs() { printf "partial\\n"; return 1; }; '
             'if pam_preserved_xattrs left right; then exit 0; else exit 99; fi', 1),
            ("generated provenance on copy",
             'pam_xattrs() { if [ "$1" = right ]; then '
             'printf "com.apple.provenance=AA\\n"; fi; }; '
             'pam_preserved_xattrs left right', 0),
            ("generated provenance preserves macl",
             'pam_xattrs() { printf "com.apple.macl=11\\n"; '
             'if [ "$1" = right ]; then printf "com.apple.provenance=AA\\n"; fi; }; '
             'pam_preserved_xattrs left right', 0),
            ("changed existing provenance",
             'pam_xattrs() { if [ "$1" = left ]; then '
             'printf "com.apple.provenance=AA\\n"; else printf "com.apple.provenance=BB\\n"; fi; }; '
             'pam_preserved_xattrs left right', 1),
            ("missing existing macl",
             'pam_xattrs() { if [ "$1" = left ]; then '
             'printf "com.apple.macl=11\\n"; else printf "com.apple.provenance=AA\\n"; fi; }; '
             'pam_preserved_xattrs left right', 1),
            ("unexpected additional macl",
             'pam_xattrs() { if [ "$1" = right ]; then '
             'printf "com.apple.macl=11\\n"; fi; }; '
             'pam_preserved_xattrs left right', 1),
            ("same metadata",
             'pam_metadata() { printf "saved\\n"; }; '
             'pam_metadata_matches file saved', 0),
            ("different metadata",
             'pam_metadata() { printf "changed\\n"; }; '
             'pam_metadata_matches file saved', 1),
            ("failed partial metadata",
             'pam_metadata() { printf "saved\\n"; return 1; }; '
             'if pam_metadata_matches file saved; then exit 0; else exit 99; fi', 1),
        ]
        for name, body, status in cases:
            with self.subTest(name=name):
                result = subprocess.run(
                    ["/bin/sh", "-c", "set -eu\n" + manager + "\n" + body],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(result.returncode, status, result.stderr)
                if name.startswith("failed"):
                    self.assertIn("pam_watchid: Cannot ", result.stderr)
                else:
                    self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
