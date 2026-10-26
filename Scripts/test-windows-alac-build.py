"""Malformed build inputs must not produce or reuse a qualified native package."""
import importlib.util
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('builder', Path(__file__).with_name('build-windows-alac.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def image(machine=0x8664):
    data = bytearray(128); data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 64)
    data[64:68] = b'PE\0\0'; struct.pack_into('<H', data, 68, machine)
    return data


class BuildBoundaryTests(unittest.TestCase):
    def test_archive_paths_types_collisions_and_bounds(self):
        prefix = 'ffmpeg-test'
        def member(name, kind=tarfile.REGTYPE):
            result = tarfile.TarInfo(name); result.type = kind; result.size = 1; result.mode = 0o644
            return result
        builder.validate_members([member(prefix + '/configure')], prefix)
        for item in [member('../escape'), member(prefix + '/../escape'), member('/' + prefix + '/absolute'),
                     member(prefix + '/C:escape'), member(prefix + '/bad\\path'),
                     member(prefix + '/link', tarfile.SYMTYPE), member(prefix + '/hard', tarfile.LNKTYPE)]:
            with self.subTest(name=item.name, kind=item.type), self.assertRaises(ValueError):
                builder.validate_members([item], prefix)
        with self.assertRaises(ValueError):
            builder.validate_members([member(prefix + '/Name'), member(prefix + '/name')], prefix)
        huge = member(prefix + '/large'); huge.size = 20_000_001
        with self.assertRaises(ValueError): builder.validate_members([huge], prefix)
        privileged = member(prefix + '/privileged'); privileged.mode |= 0o4000
        with self.assertRaises(ValueError): builder.validate_members([privileged], prefix)

    def test_only_minimal_alac_components_are_admitted(self):
        good = '#define CONFIG_ALAC_DECODER 1\n' + ''.join(f'#define CONFIG_{name} 0\n' for name in builder.DISABLED)
        good += ''.join(f'#define HAVE_{name} 1\n' for name in builder.REQUIRED_RUNTIME)
        self.assertEqual(builder.validate_components(good), ['CONFIG_ALAC_DECODER'])
        for config in [good + '#define CONFIG_AAC_DECODER 1\n', good.replace('CONFIG_NETWORK 0', 'CONFIG_NETWORK 1'),
                       good.replace('CONFIG_ALAC_DECODER 1', 'CONFIG_ALAC_DECODER 0')]:
            with self.assertRaises(ValueError): builder.validate_components(config)
        for name in builder.REQUIRED_RUNTIME:
            for replacement in [f'#define HAVE_{name} 0\n', '']:
                with self.assertRaises(ValueError):
                    builder.validate_components(good.replace(f'#define HAVE_{name} 1\n', replacement))

    def test_pe_architecture_and_truncation_are_observed_from_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'decoder.dll'
            for machine in (0x8664, 0xaa64):
                path.write_bytes(image(machine)); self.assertEqual(builder.pe_machine(path), machine)
            for data in [b'', b'MZ', bytes(128), image()[:70]]:
                path.write_bytes(data)
                with self.assertRaises(ValueError): builder.pe_machine(path)
            broken = image(); struct.pack_into('<I', broken, 60, 1000); path.write_bytes(broken)
            with self.assertRaises(ValueError): builder.pe_machine(path)

    def test_cache_rejects_changed_bytes_target_recipe_and_incomplete_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); inputs = {'recipe.py': 'input-hash'}
            paths = ['provider-receipt.json', 'package/skybridge_alac.dll', 'bridge/Release/skybridge_alac.dll',
                     'install/lib/avcodec.lib', 'install/lib/avutil.lib', 'install/include/libavcodec/avcodec.h',
                     'objects/config.h', 'objects/config_components.h', 'objects/ffbuild/config.mak']
            for name in paths:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(image() if name.endswith('.dll') else b'controlled fixture')
            receipt = dict(schema=1, status='built', target='windows-x64', recipeInputs=inputs,
                           files={name: builder.sha(root / name) for name in paths})
            manifest = root / 'receipt.json'
            manifest.write_text(json.dumps(receipt)); builder.verify_cached(root, 'x64', inputs)
            for changes in [dict(status='failed'), dict(target='windows-arm64'), dict(recipeInputs={}), dict(files={})]:
                manifest.write_text(json.dumps(dict(receipt, **changes)))
                with self.assertRaises(ValueError): builder.verify_cached(root, 'x64', inputs)
            manifest.write_text(json.dumps(receipt)); (root / paths[1]).write_bytes(image(0xaa64))
            with self.assertRaises(ValueError): builder.verify_cached(root, 'x64', inputs)
            receipt['files'][paths[1]] = builder.sha(root / paths[1]); manifest.write_text(json.dumps(receipt))
            with self.assertRaises(ValueError): builder.verify_cached(root, 'x64', inputs)


if __name__ == '__main__': unittest.main(verbosity=2)
