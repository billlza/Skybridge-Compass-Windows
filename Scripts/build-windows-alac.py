#!/usr/bin/env python3
"""Build the source-locked ALAC provider and native boundary with MSVC/MSYS2.

Uses only a caller-owned work directory. No global installation, compiler fallback,
system FFmpeg or baseline decoder is permitted. A cached build is admitted only
after checking its recipe, target, source/configuration and every recorded output.
Native decoding and application/device acceptance are separate subsequent gates.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'native/audio-alac'
TARGETS = {'x64': ('x86_64', 0x8664), 'ARM64': ('aarch64', 0xaa64)}
DISABLED = ['NETWORK', 'GPL', 'NONFREE', 'VERSION3', 'AVFORMAT', 'AVDEVICE',
            'AVFILTER', 'SWRESAMPLE', 'SWSCALE']
EXPORTS = {'sbalac_bridge_abi_version', 'sbalac_source_description_size',
           'sbalac_control_size', 'sbalac_result_size', 'sbalac_provider_contract_version',
           'sbalac_linked_version', 'sbalac_decoder_create', 'sbalac_decoder_decode',
           'sbalac_decoder_finish', 'sbalac_decoder_destroy'}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def checked(path, expected):
    actual = sha(path)
    if actual != expected:
        raise ValueError(f'Input/output hash differs: {path}; expected={expected}; actual={actual}')


def recipe_inputs():
    paths = [Path(__file__), Path(__file__).with_suffix('.ps1')]
    paths += [p for p in SOURCE.rglob('*') if p.is_file()]
    return {str(p.relative_to(ROOT)).replace('\\', '/'): sha(p) for p in sorted(paths)}


def validate_components(config):
    enabled = re.findall(r'^#define (CONFIG_\w+_(?:DECODER|ENCODER|DEMUXER|MUXER|PROTOCOL|FILTER|PARSER|BSF|INDEV|OUTDEV|HWACCEL)) 1$', config, re.M)
    if enabled != ['CONFIG_ALAC_DECODER']:
        raise ValueError(f'Unqualified codec components: {enabled}')
    for name in DISABLED:
        if not re.search(r'^#define CONFIG_' + name + r' 0$', config, re.M):
            raise ValueError(f'Unconfirmed disabled component: {name}')
    return enabled


def validate_members(members, prefix):
    if len(members) > 50_000 or sum(m.size for m in members) > 300_000_000:
        raise ValueError('Source archive exceeds extraction bounds')
    seen = set()
    for member in members:
        parts = PurePosixPath(member.name).parts
        if (not parts or parts[0] != prefix or '..' in parts or
                '\\' in member.name or ':' in member.name or PurePosixPath(member.name).is_absolute() or
                not (member.isdir() or member.isfile()) or member.size > 20_000_000 or member.mode & 0o7000 or
                member.name.casefold() in seen):
            raise ValueError('Source archive contains an unsafe or ambiguous entry')
        seen.add(member.name.casefold())


def pe_machine(path):
    with Path(path).open('rb') as file:
        header = file.read(64)
        if len(header) != 64 or header[:2] != b'MZ':
            raise ValueError('Native output is not a PE image')
        offset = struct.unpack_from('<I', header, 60)[0]
        if offset < 64 or offset > Path(path).stat().st_size - 24:
            raise ValueError('Invalid PE header offset')
        file.seek(offset)
        header = file.read(24)
        if header[:4] != b'PE\0\0':
            raise ValueError('Native output lacks a PE signature')
        return struct.unpack_from('<H', header, 4)[0]


def verify_cached(work, architecture, inputs):
    receipt = json.loads((work / 'receipt.json').read_text())
    if (receipt.get('schema') != 1 or receipt.get('status') != 'built' or
            receipt.get('target') != 'windows-' + architecture.lower() or receipt.get('recipeInputs') != inputs):
        raise ValueError('Existing ALAC build does not match this recipe and target; choose a new work directory')
    files = receipt.get('files')
    required = {'provider-receipt.json', 'package/skybridge_alac.dll', 'bridge/Release/skybridge_alac.dll',
                'install/lib/avcodec.lib', 'install/lib/avutil.lib', 'install/include/libavcodec/avcodec.h',
                'objects/config.h', 'objects/config_components.h', 'objects/ffbuild/config.mak'}
    if not isinstance(files, dict) or not required.issubset(files):
        raise ValueError('Existing ALAC receipt has no bound files')
    for name, digest in files.items():
        path = work / name
        if path.resolve() != path.absolute() or not path.resolve().is_relative_to(work):
            raise ValueError('Cached file escaped its build directory')
        checked(path, digest)
    if pe_machine(work / 'package/skybridge_alac.dll') != TARGETS[architecture][1]:
        raise ValueError('Cached ALAC DLL architecture differs from the target')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--architecture', choices=TARGETS, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--msys-root', type=Path)
    parser.add_argument('--inputs-dir', type=Path, help='Offline pinned source.tar.xz, source.tar.xz.asc and signing-key.asc')
    parser.add_argument('--generator', default='Visual Studio 18 2026')
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    work = args.work_dir.resolve(); inputs = recipe_inputs()
    if (work / 'receipt.json').exists():
        receipt = verify_cached(work, args.architecture, inputs)
        print(json.dumps({'status': 'verified', 'dll': str(work / 'package/skybridge_alac.dll'), 'target': receipt['target']}))
        return
    if args.verify_only:
        raise ValueError('No complete ALAC build receipt exists')
    if platform.system() != 'Windows' or os.environ.get('VSCMD_ARG_TGT_ARCH', '').lower() != args.architecture.lower():
        raise ValueError('Use the Windows PowerShell wrapper to select the actual MSVC target environment')
    if sys.version_info < (3, 12):
        raise ValueError('Python 3.12 or newer is required for filtered source extraction')
    if work.exists() or any(c.isspace() for c in str(work)):
        raise ValueError('A new work directory without spaces is required; incomplete builds are never overwritten')
    if args.msys_root is None:
        raise ValueError('An explicit MSYS2 root is required')
    msys = args.msys_root.resolve() / 'usr/bin'
    for tool in ['bash.exe', 'cygpath.exe', 'make.exe', 'patch.exe', 'gpg.exe', 'gpgv.exe']:
        if not (msys / tool).is_file():
            raise ValueError(f'Missing required build tool: {msys / tool}')
    compiler = shutil.which('cl.exe'); cmake = shutil.which('cmake.exe')
    if not compiler or not cmake or not shutil.which('dumpbin.exe'):
        raise ValueError('MSVC, dumpbin and CMake are required; no alternate toolchain is selected')
    lock = json.loads((SOURCE / 'provider-source-lock.json').read_text())
    source_lock = json.loads((SOURCE / 'source-lock.json').read_text())
    for name, digest in source_lock['files'].items():
        checked(SOURCE / name, digest)
    work.mkdir(parents=True); logs = work / 'logs'; logs.mkdir()
    env = os.environ.copy()
    for key in ['CFLAGS', 'CXXFLAGS', 'CPPFLAGS', 'LDFLAGS', 'CL', '_CL_', 'LINK', '_LINK_',
                'PKG_CONFIG_PATH', 'PKG_CONFIG_LIBDIR', 'CPATH', 'LIBRARY_PATH', 'MAKEFLAGS',
                'CC', 'CXX', 'LD', 'AR', 'AS', 'NM', 'RANLIB', 'STRIP']:
        env.pop(key, None)
    env.update(VSLANG='1033', SOURCE_DATE_EPOCH='1789951930', MSYSTEM='MSYS', MSYS2_PATH_TYPE='inherit')
    commands = []

    def run(label, argv, cwd=work, timeout=120):
        print(label, flush=True)
        record = dict(label=label, argv=[str(a) for a in argv], cwd=str(cwd),
                      startedAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
        commands.append(record)
        with (logs / (label + '.log')).open('wb') as output:
            process = subprocess.Popen(record['argv'], cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
            record['pid'] = process.pid
            (logs / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
            try:
                code = process.wait(timeout=timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                record['interrupted'] = True
                cleanup = subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=15)
                record['cleanupExitCode'] = cleanup.returncode
                code = process.wait(timeout=15)
        record.update(exitCode=code, endedAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
        (logs / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if code or record.get('interrupted'):
            raise RuntimeError(f'{label} failed; inspect {logs / (label + ".log")}')
        return (logs / (label + '.log')).read_text(errors='strict')

    def posix(path):
        return subprocess.check_output([str(msys / 'cygpath.exe'), '-u', str(path)], env=env, text=True).strip()

    def shell(label, argv, cwd=work, timeout=120):
        # Keep Microsoft's linker ahead of MSYS2's unrelated link utility.
        command = 'export PATH=' + shlex.quote(posix(Path(compiler).parent)) + ':/usr/bin:$PATH; exec ' + shlex.join([str(a) for a in argv])
        return run(label, [msys / 'bash.exe', '--noprofile', '--norc', '-c', command], cwd, timeout)

    downloads = work / 'inputs'; downloads.mkdir()
    for url_key, hash_key, name in [('archive', 'archiveSha256', 'source.tar.xz'),
                                    ('signature', 'signatureSha256', 'source.tar.xz.asc'),
                                    ('signingKey', 'signingKeySha256', 'signing-key.asc')]:
        if args.inputs_dir is not None:
            checked(args.inputs_dir / name, lock[hash_key]); shutil.copy2(args.inputs_dir / name, downloads / name)
        else:
            with urllib.request.urlopen(lock[url_key], timeout=60) as response, (downloads / name).open('xb') as output:
                total = 0
                while block := response.read(1024 * 1024):
                    total += len(block)
                    if total > 64 * 1024 * 1024:
                        raise ValueError('Pinned source download exceeded its byte limit')
                    output.write(block)
        checked(downloads / name, lock[hash_key])
    keyhome = work / 'key-verification'; keyhome.mkdir()
    keyring = keyhome / 'trustedkeys.gpg'
    shell('keyring', ['gpg', '--no-options', '--homedir', posix(keyhome), '--batch', '--dearmor',
                       '--output', posix(keyring), posix(downloads / 'signing-key.asc')])
    status = shell('signature', ['gpgv', '--homedir', posix(keyhome), '--keyring', posix(keyring), '--status-fd', '1',
                                 posix(downloads / 'source.tar.xz.asc'), posix(downloads / 'source.tar.xz')])
    if re.findall(r'^\[GNUPG:\] VALIDSIG ([A-F0-9]+) ', status, re.M) != [lock['signingKeyFingerprint']]:
        raise ValueError('Source signature does not match the pinned release signing key')
    prefix = 'ffmpeg-' + lock['version']
    with tarfile.open(downloads / 'source.tar.xz', 'r:xz') as archive:
        validate_members(archive.getmembers(), prefix)
        # All names, types and extraction bounds were checked; work is a fresh owned directory.
        archive.extractall(work, filter='data')
    source = work / prefix
    for name, digest in lock['licenses'].items():
        checked(source / name, digest)
    for kind in ['buildPatch', 'patch']:
        patch = lock[kind]; checked(SOURCE / patch['path'], patch['sha256'])
        for item in patch['files']:
            checked(source / item['path'], item['originalSha256'])
        shell(kind, ['patch', '--batch', '--fuzz=0', '-p1', '-i', posix(SOURCE / patch['path'])], source)
        for item in patch['files']:
            checked(source / item['path'], item['patchedSha256'])
    objects = work / 'objects'; objects.mkdir(); install = work / 'install'
    flags = [f'--prefix={posix(install)}', '--toolchain=msvc', '--arch=' + TARGETS[args.architecture][0], '--target-os=win32',
             '--disable-everything', '--disable-autodetect', '--disable-programs', '--disable-doc',
             '--disable-avformat', '--disable-avdevice', '--disable-avfilter', '--disable-swscale',
             '--disable-swresample', '--disable-network', '--disable-gpl', '--disable-nonfree', '--disable-version3',
             '--enable-decoder=alac', '--enable-static', '--disable-shared', '--disable-asm', '--disable-debug',
             '--optflags=-O2', '--extra-cflags=-WX -MT -guard:cf -GS', '--extra-ldflags=-WX -guard:cf']
    if args.architecture == 'ARM64':
        flags.append('--enable-cross-compile')
    shell('configure', ['sh', posix(source / 'configure'), *flags], objects, 300)
    shell('build', ['make', '-j1'], objects, 1200)
    shell('install', ['make', '-j1', 'install'], objects, 180)
    config = (objects / 'config.h').read_text() + (objects / 'config_components.h').read_text()
    components = validate_components(config)
    configuration = (objects / 'ffbuild/config.mak').read_text()
    cflags = re.search(r'^CFLAGS=(.*)$', configuration, re.M)
    if not cflags or not re.search(r'(?:^|\s)[/-]MT(?:\s|$)', cflags[1]) or re.search(r'(?:^|\s)[/-]MDd?(?:\s|$)', cflags[1]):
        raise ValueError('Provider was not compiled with the required static release CRT')
    libraries = sorted((install / 'lib').glob('*.lib'))
    if [p.name for p in libraries] != ['avcodec.lib', 'avutil.lib']:
        raise ValueError('Expected only the two minimal static provider libraries')
    checked(install / 'include/libavcodec/avcodec.h', sha(source / 'libavcodec/avcodec.h'))
    provider = dict(status='built', baseline=False, providerContract=lock['providerContract'], version=lock['version'],
                    archiveSha256=lock['archiveSha256'], source=str(source), install=str(install), components=components,
                    target='windows-' + args.architecture.lower(),
                    libraries=[dict(path=str(p), sha256=sha(p)) for p in libraries])
    provider_path = work / 'provider-receipt.json'; provider_path.write_text(json.dumps(provider, indent=2) + '\n')
    bridge = work / 'bridge'
    run('bridge-configure', [cmake, '-S', SOURCE, '-B', bridge, '-G', args.generator, '-A', args.architecture,
                             '-DSKYBRIDGE_ALAC_PROVIDER_RECEIPT=' + str(provider_path)])
    run('bridge-build', [cmake, '--build', bridge, '--config', 'Release', '--parallel', '1'], timeout=300)
    dll = bridge / 'Release/skybridge_alac.dll'
    if pe_machine(dll) != TARGETS[args.architecture][1]:
        raise ValueError('Native DLL does not match its requested architecture')
    exports = run('exports', ['dumpbin.exe', '/nologo', '/exports', dll])
    actual_exports = set(re.findall(r'^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]+\s+(\S+)', exports, re.M))
    if actual_exports != EXPORTS:
        raise ValueError(f'Native export contract differs: {actual_exports}')
    imports = run('imports', ['dumpbin.exe', '/nologo', '/dependents', dll])
    dependencies = set(re.findall(r'^\s+(\S+\.dll)\s*$', imports, re.M | re.I))
    allowed = {'kernel32.dll', 'advapi32.dll', 'user32.dll', 'bcrypt.dll'}
    if not dependencies or {x.lower() for x in dependencies} - allowed:
        raise ValueError(f'Unqualified DLL runtime dependencies: {dependencies}')
    package = work / 'package'; package.mkdir(); shutil.copy2(dll, package / dll.name)
    licenses = package / 'Licenses'; licenses.mkdir()
    for name in ['COPYING.LGPLv2.1', 'LICENSE.md', 'LICENSE.SkyBridge', 'provider-source-lock.json', 'source-lock.json']:
        shutil.copy2(SOURCE / name, licenses / ('ALAC-' + name))
    # Preserve reproducible source/relink inputs separately from the runtime package.
    relink = work / 'source-materials'; relink.mkdir()
    for name in ['source.tar.xz', 'source.tar.xz.asc', 'signing-key.asc']:
        shutil.copy2(downloads / name, relink / name)
    shutil.copytree(SOURCE, relink / 'native/audio-alac')
    (relink / 'Scripts').mkdir()
    shutil.copy2(Path(__file__), relink / 'Scripts' / Path(__file__).name)
    shutil.copy2(Path(__file__).with_suffix('.ps1'), relink / 'Scripts' / Path(__file__).with_suffix('.ps1').name)
    bound = [provider_path, dll, *libraries, install / 'include/libavcodec/avcodec.h',
             objects / 'config.h', objects / 'config_components.h', objects / 'ffbuild/config.mak']
    for patch in [lock['buildPatch'], lock['patch']]:
        bound += [source / item['path'] for item in patch['files']]
    bound += [p for d in [package, relink] for p in d.rglob('*') if p.is_file()]
    if inputs != recipe_inputs():
        raise ValueError('Recipe or boundary changed during compilation')
    receipt = dict(schema=1, status='built', target=provider['target'], recipeInputs=inputs,
                   files={str(p.relative_to(work)).replace('\\', '/'): sha(p) for p in sorted(set(bound))},
                   compiler=dict(path=compiler, sha256=sha(compiler), toolsVersion=os.environ.get('VCToolsVersion')),
                   dependencies=sorted(dependencies), exports=sorted(actual_exports),
                   nativeDecoderTests='not-run', applicationBuild='not-run', devicePlayback='not-run',
                   finishedAt=datetime.datetime.now(datetime.timezone.utc).isoformat())
    temporary = work / 'receipt.pending.json'; temporary.write_text(json.dumps(receipt, indent=2) + '\n')
    temporary.replace(work / 'receipt.json')
    print(json.dumps({'status': 'built', 'dll': str(package / dll.name), 'target': receipt['target']}))


if __name__ == '__main__':
    main()
