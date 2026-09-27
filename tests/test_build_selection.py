"""Check Make's CPU selection without compiling or changing machine state."""

from pathlib import Path
import subprocess
import unittest

PROJECT = Path(__file__).resolve().parents[1]


class BuildSelectionTests(unittest.TestCase):
    def invoke(self, *variables, target="build"):
        return subprocess.run(
            ["/usr/bin/make", "--no-print-directory", "-n", target, *variables],
            cwd=PROJECT, text=True, capture_output=True,
        )

    def test_native_and_rosetta_selection(self):
        for process, translated, expected in (
            ("arm64", "0", "arm64"),
            ("x86_64", "1", "arm64"),
        ):
            with self.subTest(process=process, translated=translated):
                result = self.invoke(f"PROCESS_ARCH={process}", f"TRANSLATED={translated}")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.count(f"-arch {expected} "), 2)
                self.assertEqual(result.stdout.count("-mmacosx-version-min=15.0"), 2)

    def test_all_build_targets_emit_only_arm64(self):
        for target in ("build", "build-all", "build-arm64", "check"):
            with self.subTest(target=target):
                result = self.invoke("PROCESS_ARCH=arm64", "ARCH=arm64", target=target)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("-arch arm64 ", result.stdout)
                self.assertNotIn("-arch x86_64", result.stdout)
                self.assertNotIn("build/x86_64", result.stdout)
        self.assertNotEqual(self.invoke(target="build-x86_64").returncode, 0)

    def test_unsupported_or_unknown_architecture_fails(self):
        for variables in (
            ("PROCESS_ARCH=unknown",),
            ("PROCESS_ARCH=x86_64", "TRANSLATED="),
            ("PROCESS_ARCH=x86_64", "TRANSLATED=0"),
            ("PROCESS_ARCH=x86_64", "TRANSLATED=0", "ARCH=arm64"),
            ("PROCESS_ARCH=x86_64", "TRANSLATED=unavailable"),
            ("PROCESS_ARCH=x86_64", "TRANSLATED=2"),
            ("ARCH=unknown",),
            ("ARCH=x86_64",),
            ("ARCH=arm64 x86_64",),
            ("ARCH=",),
        ):
            with self.subTest(variables=variables):
                self.assertNotEqual(self.invoke(*variables).returncode, 0)


if __name__ == "__main__":
    unittest.main()
