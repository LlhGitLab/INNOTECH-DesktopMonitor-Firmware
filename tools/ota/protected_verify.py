"""Public verification of sec2 ciphertext and board-specific signed wrappers."""
from pathlib import Path
import re
import struct
from functools import reduce
from operator import xor
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from . import release

PROFILE = release.PROTECTED_PROFILE
MANIFEST = 'manifest-' + PROFILE + '.json'
WRAPPER_BYTES = 320
LEGACY_MAX_RECIPIENTS = 998
MAX_RECIPIENTS = 10000
GROUP_RECORD_BYTES = 6 + WRAPPER_BYTES
GROUP_NAME = re.compile(r'keygroup-([0-9a-f]{2})\.bin')
WRAPPER_NAME = re.compile(r'key-([0-9a-f]{12})\.bin')
_WRAP_DOMAIN = b'INNO-OTA-WRAP1'

def no_links(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('unexpected symbolic link')
    return path

def read_regular(path, limit):
    path = no_links(path)
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError('invalid release file')
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('oversized release file')
    return data

def _sequence_bytes(sequence):
    if type(sequence) is not int or not 0 < sequence <= 0xffffffff:
        raise ValueError('invalid OTA sequence')
    return struct.pack('<I', sequence)

def _mac(value):
    if type(value) is not bytes or len(value) != 6 or value in (bytes(6), b'\xff' * 6):
        raise ValueError('invalid hardware MAC')
    return value

def wrapper_filename(mac):
    return 'key-' + _mac(mac).hex() + '.bin'

def group_filename(mac):
    return f'keygroup-{reduce(xor, _mac(mac)):02x}.bin'

def parse_group(name, data):
    if (not GROUP_NAME.fullmatch(name) or not 0 < len(data) <= GROUP_RECORD_BYTES * MAX_RECIPIENTS
            or len(data) % GROUP_RECORD_BYTES):
        raise ValueError('invalid recipient group')
    members = {}
    previous = b''
    for offset in range(0, len(data), GROUP_RECORD_BYTES):
        mac = data[offset:offset + 6]
        if group_filename(mac) != name or mac <= previous:
            raise ValueError('misplaced, unsorted or duplicate recipient')
        members[mac] = data[offset + 6:offset + GROUP_RECORD_BYTES]
        previous = mac
    return members

def distribution_files(directory, wrappers):
    """Reconstruct only verified bytes; require the exact original names and layout."""
    names = {path.name for path in Path(directory).iterdir()} - {MANIFEST, release.PROTECTED_ARTIFACT}
    if all(WRAPPER_NAME.fullmatch(name) for name in names):
        files = {wrapper_filename(mac): wrapper for mac, wrapper in wrappers.items()}
    else:
        groups = {}
        for mac, wrapper in sorted(wrappers.items()):
            groups.setdefault(group_filename(mac), bytearray()).extend(mac + wrapper)
        files = {name: bytes(group) for name, group in groups.items()}
    if files.keys() != names:
        raise ValueError('recipient dataset changed')
    return files

def _wrapper_aad(mac, sequence, ciphertext_sha256):
    if type(ciphertext_sha256) is not bytes or len(ciphertext_sha256) != 32:
        raise ValueError('invalid ciphertext digest')
    return _WRAP_DOMAIN + _mac(mac) + _sequence_bytes(sequence) + ciphertext_sha256

def verify_wrapper(wrapper, mac, sequence, ciphertext_sha256, public_key):
    release.key_ok(public_key)
    aad = _wrapper_aad(mac, sequence, ciphertext_sha256)
    if type(wrapper) is not bytes or len(wrapper) != WRAPPER_BYTES or wrapper[:4] != b'IOK1':
        raise ValueError('invalid protected OTA wrapper')
    try:
        public_key.verify(wrapper[64:], wrapper[:64] + aad, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise ValueError('protected OTA wrapper signature failed') from exc

def _verified_release(directory, ota_public_key):
    directory = no_links(directory)
    if not directory.is_dir():
        raise ValueError('dedicated protected OTA directory required')
    envelope = read_regular(directory / MANIFEST, 4096)
    fields = release.authenticate(envelope, ota_public_key)
    if fields['profile'] != PROFILE:
        raise ValueError('protected OTA profile required')
    ciphertext = read_regular(directory / release.PROTECTED_ARTIFACT, release.image_limit(fields, release.MAX_IMAGE))
    release.verify(envelope, ciphertext, ota_public_key)
    return directory, envelope, ciphertext, fields

def read_release(directory, ota_public_key):
    """Return authenticated envelope, ciphertext, and per-device wrapper bytes."""
    directory, envelope, ciphertext, fields = _verified_release(directory, ota_public_key)
    wrappers = {}
    digest = bytes.fromhex(fields['sha256'])
    paths = [path for path in directory.iterdir() if path.name not in (MANIFEST, release.PROTECTED_ARTIFACT)]
    legacy = all(WRAPPER_NAME.fullmatch(path.name) for path in paths)
    if len(paths) > (LEGACY_MAX_RECIPIENTS if legacy else 256):
        raise ValueError('too many protected OTA release files')
    for path in paths:
        if legacy:
            mac = bytes.fromhex(WRAPPER_NAME.fullmatch(path.name)[1])
            members = {mac: read_regular(path, WRAPPER_BYTES)}
        else:
            available = (MAX_RECIPIENTS - len(wrappers)) * GROUP_RECORD_BYTES
            if not GROUP_NAME.fullmatch(path.name) or not available:
                raise ValueError('unexpected protected OTA release file')
            members = parse_group(path.name, read_regular(path, available))
        for mac, wrapper in members.items():
            verify_wrapper(wrapper, mac, fields['sequence'], digest, ota_public_key)
        wrappers.update(members)
    if not wrappers:
        raise ValueError('protected OTA release needs enrolled devices')
    return envelope, ciphertext, wrappers

