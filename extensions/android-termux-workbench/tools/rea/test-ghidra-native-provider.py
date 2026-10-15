#!/usr/bin/env python
import importlib.util
import pathlib
import shutil
import unittest
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / 'run/rea-b06dd042'
SPEC = importlib.util.spec_from_file_location('ghidra_native', ROOT / 'tools/rea/ghidra-native-provider.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GhidraNativeProviderTest(unittest.TestCase):
    def setUp(self):
        self.job = 'test-native-' + uuid.uuid4().hex[:12]

    def tearDown(self):
        shutil.rmtree(BASE / 'native-jobs' / self.job, ignore_errors=True)

    def test_real_arm64_elf_decompile(self):
        result = MODULE.analyze(BASE / 'samples/owned.elf', None, 'owned_add', self.job, 120)
        self.assertEqual(result['status'], 'VERIFIED')
        self.assertEqual(result['evidence']['selected_function'], 'owned_add')
        self.assertTrue(result['evidence']['instructions'])
        self.assertEqual(result['evidence']['decompiled_fidelity'], 'decompiled_approx')
        self.assertIn('callers', result['evidence'])
        self.assertIn('callees', result['evidence'])


    def test_selector_validation(self):
        with self.assertRaisesRegex(ValueError, 'NATIVE_SELECTOR_CONFLICT'):
            MODULE.analyze(BASE / 'samples/owned.elf', None, 'owned_add', self.job, 120, address='0')
        with self.assertRaisesRegex(ValueError, 'INVALID_NATIVE_ADDRESS'):
            MODULE.analyze(BASE / 'samples/owned.elf', None, None, self.job, 120, address='not-hex')
        with self.assertRaisesRegex(ValueError, 'INVALID_NATIVE_STRING'):
            MODULE.analyze(BASE / 'samples/owned.elf', None, None, self.job, 120, string_query='')

    def test_member_scope_rejects_arbitrary_path(self):
        root = BASE / 'native-jobs' / self.job
        root.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, 'APK_NATIVE_MEMBER_REQUIRED'):
            MODULE.prepare_input(BASE / 'samples/owned-native-profile.apk', '../lib.so', root)


if __name__ == '__main__':
    unittest.main()
