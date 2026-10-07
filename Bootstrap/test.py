"""Check installer assembly, then run the selected component test modules."""

import argparse
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEST_DIRECTORIES = ("Bootstrap.Tests", "Packages.Tests", "Updates.Tests")
MODULES = (
    "test_bundle",
    "test_bootstrap",
    "test_package_admission",
    "test_update_staging",
    "test_update_compatibility",
    "test_update_capacity",
    "test_update_effects",
    "test_update_interpreters",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("modules", nargs="*", choices=MODULES,
                        help="test modules to run; defaults to every component")
    args = parser.parse_args()
    result = subprocess.run([sys.executable, "-B", str(ROOT / "Bootstrap/pack.py"), "--check"],
                            check=False)
    if result.returncode:
        return result.returncode
    # Legacy fixture imports stay local to the three test components. The
    # delivered installer never imports or depends on this development runner.
    sys.path[:0] = [str(ROOT / directory) for directory in TEST_DIRECTORIES]
    loader = unittest.TestLoader()
    suite = unittest.TestSuite(loader.loadTestsFromName(name) for name in (args.modules or MODULES))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
