#!/usr/bin/env python
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / "run/rea-b06dd042"
sys.path.insert(0, str(ROOT / "tools/rea"))
from android_signature import verify_target


def call(argv):
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def make_key(path, alias):
    call([
        "keytool", "-genkeypair", "-keystore", str(path),
        "-storepass", "changeit", "-keypass", "changeit",
        "-alias", alias, "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "30", "-dname", f"CN={alias},O=REA Local,C=CN",
    ])


def sign(apk, key, alias):
    call([
        "apksigner", "sign", "--ks", str(key), "--ks-pass", "pass:changeit",
        "--key-pass", "pass:changeit", "--ks-key-alias", alias,
        "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "true", str(apk),
    ])


class AndroidSignatureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = pathlib.Path(tempfile.mkdtemp(prefix="signature-test-", dir=BASE / "inbox"))
        cls.source = BASE / "samples/owned.apk"
        cls.key_a = cls.work / "a.jks"
        cls.key_b = cls.work / "b.jks"
        make_key(cls.key_a, "signer-a")
        make_key(cls.key_b, "signer-b")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def test_v1_v2_v3_v4_real_verification(self):
        apk = self.work / "signed.apk"
        shutil.copy2(self.source, apk)
        sign(apk, self.key_a, "signer-a")
        result = verify_target(apk)
        package = result["package_results"][0]
        self.assertTrue(result["verified"])
        self.assertTrue(all(package["schemes"][name] for name in ("v1", "v2", "v3", "v4")))
        self.assertEqual(package["v4"], "VERIFIED")
        self.assertEqual(len(package["certificate_sha256"]), 1)

    def test_unsigned_is_not_reported_verified(self):
        apk = self.work / "unsigned.apk"
        shutil.copy2(self.source, apk)
        result = verify_target(apk)
        self.assertFalse(result["verified"])
        self.assertEqual(result["trust_statement"], "NOT_VERIFIED")

    def test_split_signer_mismatch_is_rejected(self):
        split = self.work / "splits"
        split.mkdir()
        base = split / "base.apk"
        feature = split / "split_feature.apk"
        shutil.copy2(self.source, base)
        shutil.copy2(self.source, feature)
        sign(base, self.key_a, "signer-a")
        sign(feature, self.key_b, "signer-b")
        result = verify_target(split)
        self.assertFalse(result["verified"])
        self.assertFalse(result["signer_consistent"])


if __name__ == "__main__":
    unittest.main()
