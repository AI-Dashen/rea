#!/usr/bin/env python
import importlib.util, json, pathlib, shutil, sqlite3, sys, unittest, uuid, zipfile
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/rea"))

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools/rea" / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
DEX = load("dex_layer_tested", "dex_layer.py")
DIFF = load("android_version_diff_tested", "android_version_diff.py")

class DexLayerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.token = uuid.uuid4().hex[:10]
        cls.old_job = f"test-dex-old-{cls.token}"; cls.new_job = f"test-dex-new-{cls.token}"
        cls.diff_job = f"test-diff-{cls.token}"
        cls.created = [DEX.JOBS / cls.old_job, DEX.JOBS / cls.new_job, DIFF.DIFFS / cls.diff_job]
        cls.fixture_dir = DEX.BASE / "inbox" / f"dex-layer-test-{cls.token}"; cls.fixture_dir.mkdir(parents=True)
        cls.created.append(cls.fixture_dir)
        cls.old = DEX.build_index(DEX.BASE / "samples/owned.apk", cls.old_job)
        cls.new = DEX.build_index(DEX.BASE / "samples/owned-advanced.apk", cls.new_job)
    @classmethod
    def tearDownClass(cls):
        for path in cls.created: shutil.rmtree(path, ignore_errors=True)
    def test_indexes_all_symbol_layers_and_checkpoint(self):
        self.assertEqual(self.old["status"], "VERIFIED")
        self.assertEqual(self.old["evidence_graph_v2"]["schema_version"], "2.0")
        self.assertEqual(len(self.old["evidence_graph_v2"]["nodes"]), 2)
        self.assertGreater(self.old["counts"]["strings"], 0)
        self.assertGreater(self.old["counts"]["classes"], 0)
        self.assertGreater(self.old["counts"]["declared_methods"], 0)
        checkpoint = json.loads((DEX.JOBS / self.old_job / "checkpoint.json").read_text())
        self.assertEqual(checkpoint["state"], "COMPLETED")
        results = DEX.search_index(DEX.JOBS / self.old_job, "OwnedArithmetic", "class")
        self.assertEqual(results[0]["java_name"], "owned.acceptance.OwnedArithmetic")
    def test_resume_reuses_verified_dex_unit(self):
        result = DEX.build_index(DEX.BASE / "samples/owned.apk", self.old_job, resume=True)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertTrue(result["units"][0]["resumed"])
    def test_exact_class_is_decompiled_on_demand(self):
        result = DEX.decompile_class(DEX.JOBS / self.old_job, "owned.acceptance.OwnedArithmetic", 60)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertRegex(result.get("decompiler", {}).get("config_sha256", ""), r"^[0-9a-f]{64}$")
        source = ROOT / result["source"]
        self.assertIn("class OwnedArithmetic", source.read_text())
        with self.assertRaisesRegex(ValueError, "CLASS_NOT_INDEXED"):
            DEX.decompile_class(DEX.JOBS / self.old_job, "owned.acceptance.DoesNotExist", 60)
    def test_failed_dex_is_never_reported_verified(self):
        bad = self.fixture_dir / "bad.apk"
        with zipfile.ZipFile(bad, "w") as archive:
            archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00manifest")
            archive.writestr("classes.dex", b"dex\n038\x00" + b"\x00" * 104)
        job = f"test-dex-bad-{self.token}"; self.created.append(DEX.JOBS / job)
        result = DEX.build_index(bad, job)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["layers"]["on_demand_decompilation"], "UNAVAILABLE")
        checkpoint = json.loads((DEX.JOBS / job / "checkpoint.json").read_text())
        self.assertEqual(checkpoint["state"], "FAILED")
    def test_index_paths_are_scoped(self):
        with self.assertRaisesRegex(ValueError, "INDEX_DENIED"):
            DEX.ensure_index(ROOT / "AGENTS.md")
    def test_version_diff_keeps_complete_changes_in_sqlite(self):
        result = DIFF.build_diff(DEX.JOBS / self.old_job, DEX.JOBS / self.new_job, self.diff_job)
        self.assertEqual(result["status"], "VERIFIED")
        self.assertGreater(result["change_count"], 0)
        self.assertEqual(result["evidence_graph_v2"]["schema_version"], "2.0")
        self.assertEqual(len(result["evidence_graph_v2"]["nodes"]), 1)
        self.assertEqual(result["counts"]["native_library"]["ADDED"], 1)
        self.assertEqual(result["counts"]["dex_member"]["CHANGED"], 1)
        database = ROOT / result["changes_database"]
        connection = sqlite3.connect(database)
        try: count = connection.execute("SELECT count(*) FROM changes").fetchone()[0]
        finally: connection.close()
        self.assertEqual(count, result["change_count"])
        checkpoint = json.loads((DIFF.DIFFS / self.diff_job / "checkpoint.json").read_text())
        self.assertEqual(checkpoint["state"], "COMPLETED")

if __name__ == "__main__": unittest.main()
