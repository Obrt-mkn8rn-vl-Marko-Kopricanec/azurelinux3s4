"""Check installer assembly, then run the selected component test modules."""

import argparse
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
TEST_DIRECTORIES = ("Bootstrap.Tests", "Packages.Tests", "Updates.Tests", "Web.Tests", "SSH.Tests", "Deployment.Tests")
MODULES = (
    "test_bundle",
    "test_bootstrap",
    "test_package_admission",
    "test_update_staging",
    "test_update_compatibility",
    "test_update_capacity",
    "test_update_boot_budget",
    "test_update_initramfs",
    "test_update_effects",
    "test_update_triggers",
    "test_update_trigger_prefixes",
    "test_update_trigger_conditions",
    "test_update_trigger_ranges",
    "test_update_provides",
    "test_update_provider_matches",
    "test_update_trigger_sources",
    "test_update_header_inputs",
    "test_update_header_matches",
    "test_update_trigger_first",
    "test_update_header_iteration",
    "test_update_trigger_counts",
    "test_update_trigger_arguments",
    "test_update_trigger_iterators",
    "test_update_trigger_walk",
    "test_update_transaction_elements",
    "test_update_psm_goals",
    "test_update_psm_inputs",
    "test_update_psm_routes",
    "test_update_psm_failures",
    "test_update_psm_verification",
    "test_update_interpreters",
    "test_update_interpreter_paths",
    "test_update_kernel_layout",
    "test_update_removals",
    "test_update_versions",
    "test_update_baselines",
    "test_update_floors",
    "test_update_kernel_paths",
    "test_web_isolation",
    "test_web_relay",
    "test_web_admission",
    "test_web_filesystem",
    "test_web_operations",
    "test_web_runtime",
    "test_web_memory",
    "test_web_descriptors",
    "test_web_resources",
    "test_ssh_policy",
    "test_ssh_keys",
    "test_ssh_crypto",
    "test_ssh_revocations",
    "test_ssh_accounts",
    "test_ssh_home",
    "test_ssh_service",
    "test_deployment_policy",
    "test_deployment_publication",
    "test_deployment_releases",
    "test_deployment_runtime_metadata",
    "test_deployment_dependency_metadata",
    "test_deployment_services",
    "test_deployment_credentials",
    "test_deployment_dns_configuration",
    "test_deployment_email_credentials",
    "test_deployment_email_role_policy",
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
    # Fixture imports stay local to the explicit test components. The
    # delivered installer never imports or depends on this development runner.
    sys.path[:0] = [str(ROOT / directory) for directory in TEST_DIRECTORIES]
    loader = unittest.TestLoader()
    suite = unittest.TestSuite(loader.loadTestsFromName(name) for name in (args.modules or MODULES))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
