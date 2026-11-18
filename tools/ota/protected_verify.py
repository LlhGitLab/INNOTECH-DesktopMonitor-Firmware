"""Public verification of sec2 ciphertext and board-specific signed wrappers."""
from pathlib import Path
import re
import struct
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from . import release

PROFILE = release.PROTECTED_PROFILE
MANIFEST = 'manifest-' + PROFILE + '.json'
WRAPPER_BYTES = 320
MAX_RECIPIENTS = 998
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
    for path in directory.iterdir():
        if path.name in (MANIFEST, release.PROTECTED_ARTIFACT):
            continue
        match = WRAPPER_NAME.fullmatch(path.name)
        if not match or len(wrappers) >= MAX_RECIPIENTS:
            raise ValueError('unexpected protected OTA release file')
        mac = bytes.fromhex(match[1])
        wrapper = read_regular(path, WRAPPER_BYTES)
        verify_wrapper(wrapper, mac, fields['sequence'], digest, ota_public_key)
        wrappers[mac] = wrapper
    if not wrappers:
        raise ValueError('protected OTA release needs enrolled devices')
    return envelope, ciphertext, wrappers

