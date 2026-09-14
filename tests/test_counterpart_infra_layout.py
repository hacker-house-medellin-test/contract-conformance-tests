import pathlib
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest

SOURCE_REPO = "https://github.com/hacker-house-medellin/hhm-infra.git"
SOURCE_SHA = "fefdd8a0224a86a6a9d3fff65a847929c412aa5a"
ENVIRONMENTS = ("preview", "staging", "production")
PROVIDER_NATIVE_NAMES = {"wrangler.toml", "wrangler.json", "wrangler.jsonc", "neon.ts"}


def run(*args: str, cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


@unittest.skipUnless(shutil.which("terraform"), "Terraform is exercised by the dedicated infra counterpart workflow")
class CounterpartInfraLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="hhm-infra-contract-")
        cls.root = pathlib.Path(cls._tmp.name) / "infra"
        cls.root.mkdir()
        run("git", "init", "-q", cwd=cls.root)
        run("git", "remote", "add", "origin", SOURCE_REPO, cwd=cls.root)
        run("git", "fetch", "--depth=1", "origin", SOURCE_SHA, cwd=cls.root)
        run("git", "checkout", "--detach", "FETCH_HEAD", cwd=cls.root)
        cls.manifest = tomllib.loads((cls.root / ".ores-infra.toml").read_text())

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def test_modules_first_provider_roots(self) -> None:
        self.assertEqual(self.manifest["schema_version"], 1)
        self.assertEqual(self.manifest["layout"], "modules")
        self.assertEqual(self.manifest["modules_root"], "modules")
        self.assertEqual(self.manifest["environments_root"], "environments")
        providers = self.manifest["providers"]
        self.assertEqual(providers["supabase"]["canonical_path"], "modules/supabase")
        self.assertEqual(providers["supabase"]["native_working_directory"], "modules")
        self.assertEqual(providers["cloudflare"]["canonical_path"], "modules/cloudflare")
        self.assertEqual(providers["neon"]["project_root"], "modules/neon")
        self.assertEqual(providers["neon"]["config"], "modules/neon/neon.ts")
        self.assertEqual(self.manifest["policy"]["state_isolation"], "per-provider-per-environment")

    def test_terraform_environments_validate(self) -> None:
        run("terraform", "fmt", "-check", "-recursive", "modules/cloudflare/terraform", cwd=self.root)
        for environment in ENVIRONMENTS:
            env_root = self.root / "environments" / environment
            main_tf = env_root / "main.tf"
            self.assertTrue(main_tf.is_file(), main_tf)
            text = main_tf.read_text()
            self.assertIn('backend "s3" {}', text)
            self.assertRegex(text, r'source\s*=\s*"\.\./\.\./modules/cloudflare/terraform/worker-shell"')
            self.assertRegex(text, rf'environment\s*=\s*"{re.escape(environment)}"')
            run("terraform", "fmt", "-check", "-recursive", ".", cwd=env_root)
            run("terraform", "init", "-backend=false", "-input=false", cwd=env_root)
            run("terraform", "validate", "-no-color", cwd=env_root)

    def test_environments_do_not_commit_provider_native_source_or_state(self) -> None:
        tracked = run("git", "ls-files", "environments", cwd=self.root).stdout.splitlines()
        self.assertTrue(tracked)
        for relative in tracked:
            path = pathlib.PurePosixPath(relative)
            self.assertNotIn(path.name, PROVIDER_NATIVE_NAMES, relative)
            self.assertNotIn("supabase", path.parts, relative)
            self.assertFalse(path.name.endswith(".tfstate"), relative)
            self.assertNotIn(".terraform", path.parts, relative)

    def test_worker_shell_is_opt_in(self) -> None:
        text = (self.root / "modules/cloudflare/terraform/worker-shell/main.tf").read_text()
        self.assertIn('variable "enabled"', text)
        self.assertIn("default = false", text)
        self.assertIn("var.enabled ? 1 : 0", text)


if __name__ == "__main__":
    unittest.main()
