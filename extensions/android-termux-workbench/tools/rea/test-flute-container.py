#!/usr/bin/env python
import importlib.util, pathlib, shutil, struct, unittest, uuid
ROOT=pathlib.Path(__file__).resolve().parents[2]
BASE=ROOT/'run/rea-b06dd042'
SPEC=importlib.util.spec_from_file_location('flute_container',ROOT/'tools/rea/flute_container.py')
MODULE=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MODULE)

def build(path, names_payloads, mutate=None):
    table_size=sum(len(name.encode())+1+24 for name,_ in names_payloads)
    data_offset=21+table_size; cursor=data_offset; rows=[]
    for name,payload in names_payloads:
        rows.append([name,cursor,len(payload),0x6a3bc9dd]); cursor+=len(payload)
    if mutate: mutate(rows,data_offset,cursor)
    data=bytearray(b'FLUTE'+struct.pack('<IQI',2,data_offset,len(rows)))
    for name,offset,size,tag in rows:
        data.extend(name.encode()+b'\0'+struct.pack('<QQQ',offset,size,tag))
    for _,payload in names_payloads: data.extend(payload)
    path.write_bytes(data)

class FluteContainerTest(unittest.TestCase):
    def setUp(self):
        self.root=BASE/'inbox'/('flute-test-'+uuid.uuid4().hex[:10]); self.root.mkdir(parents=True)
    def tearDown(self): shutil.rmtree(self.root,ignore_errors=True)
    def test_valid_inventory_hash_and_magic(self):
        target=self.root/'valid.flute'; build(target,[('/config.json',b'{"ok":true}'),('/model.bin',b'\x00\x01model')])
        result=MODULE.inspect_flute(target)
        self.assertEqual(result['status'],'VERIFIED'); self.assertEqual(result['entry_count'],2)
        self.assertEqual(result['entries'][0]['detected_magic'],'JSON_OBJECT')
        self.assertEqual(result['entries'][0]['path'],'/config.json')
        self.assertEqual(len(result['entries'][1]['sha256']),64)
    def test_traversal_rejected(self):
        target=self.root/'traversal.flute'; build(target,[('../secret',b'x')])
        with self.assertRaisesRegex(ValueError,'FLUTE_UNSAFE_PATH'): MODULE.inspect_flute(target)
    def test_overlap_rejected(self):
        target=self.root/'overlap.flute'
        def mutate(rows,data_offset,cursor): rows[1][1]=rows[0][1]
        build(target,[('/a',b'aaaa'),('/b',b'bbbb')],mutate)
        with self.assertRaisesRegex(ValueError,'FLUTE_ENTRY_OVERLAP'): MODULE.inspect_flute(target)
    def test_out_of_bounds_rejected(self):
        target=self.root/'bounds.flute'
        def mutate(rows,data_offset,cursor): rows[0][2]=cursor+1
        build(target,[('/a',b'a')],mutate)
        with self.assertRaisesRegex(ValueError,'FLUTE_ENTRY_BOUNDS'): MODULE.inspect_flute(target)
if __name__=='__main__': unittest.main()
