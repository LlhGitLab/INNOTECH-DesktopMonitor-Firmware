"""Offline, explicit BIN-only RSA2048 OTA publication package. No key generation."""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

FIELDS = {"schema","channel","sequence","version","profile","tag","artifact","size","sha256","image_signature"}
MAX_IMAGE = 1044464
MARKER = b"INNOTECH_OTA_META_V1|"
BRAND_PREFIX = b"INNOTECH_BRAND_V1|"
BRAND_RECORD = b"INNOTECH_BRAND_V1|name=INNOTECH|short=INNO|ssid=3DPrint-Monitor-INNO|policy=software-basic|"
BRAND_SEQUENCE = 27
SAFE1_PROFILE = "esp8266-st7789-154-safe1"
SAFE1_PREFIX_SHA256 = "75892b1457444b0aed6dad12dffcbce8c8cdf576b461e7d7c1cb1c9a11ece121"

def _crc8266(data):
    """Core3.1.2 elf2bin MSB-first CRC, with the caller zeroing SDK fields."""
    table=[]
    for byte in range(256):
        crc=byte<<24
        for _ in range(8):
            crc=((crc<<1)^(0x04c11db7 if crc&0x80000000 else 0))&0xffffffff
        table.append(crc)
    crc=0xffffffff
    for byte in data:crc=((crc<<8)&0xffffffff)^table[(crc>>24)^byte]
    return crc

def _check_safe1_image(image):
    """Validate this existing public Core3.1.2 safe1 layout without any SDK/ELF."""
    if not 0x1018<=len(image)<=MAX_IMAGE:raise ValueError("invalid safe1 image extent")
    if hashlib.sha256(image[:4096]).hexdigest()!=SAFE1_PREFIX_SHA256:
        raise ValueError("safe1 loader prefix mismatch")
    if b"SBTEST" in image:raise ValueError("private fixture hook in public safe1 image")
    if image[4096:4100]!=b"\xe9\x05\x02\x40":raise ValueError("invalid safe1 application header")
    entry=struct.unpack_from('<I',image,4100)[0]
    # elf2bin serializes .irom0.text,.text,.text1,.data,.rodata in this order.
    ranges=((0x40201010,0x40300000),(0x40100000,0x4010c000),(0x40100000,0x4010c000),
            (0x3ffe8000,0x3fffc000),(0x3ffe8000,0x3fffc000))
    segments=[];pos=4104
    for index,(low,high) in enumerate(ranges):
        if pos+8>len(image):raise ValueError("truncated safe1 segment header")
        address,size=struct.unpack_from('<II',image,pos);pos+=8
        if (not size or size>len(image)-pos or address&3 or
                not low<=address<high or size>high-address):
            raise ValueError("invalid safe1 segment extent")
        if index==0 and (address!=0x40201010 or size<8):
            raise ValueError("invalid safe1 IROM CRC area")
        if any(address<other+length and other<address+size for other,length,_ in segments):
            raise ValueError("overlapping safe1 segments")
        segments.append((address,size,pos));pos+=size
    if entry&3 or not any(a<=entry<a+n for a,n,_ in segments[1:3]):
        raise ValueError("safe1 entry outside application IRAM")
    # write_bin pads with zeroes then puts the XOR at the last byte of16B.
    end=(pos+16)&~15
    if end!=len(image) or any(image[pos:end-1]):raise ValueError("invalid safe1 padding or trailing bytes")
    declared,stored_crc=struct.unpack_from('<II',image,0x1010)
    if declared!=len(image):raise ValueError("safe1 SDK image length mismatch")
    raw=bytearray(image);raw[0x1010:0x1018]=bytes(8)
    checksum=0xef
    # Linker LONG(0),LONG(0) precede IROM. add_crc patches those8 bytes after
    # calculating section XOR and deliberately does not recalculate the XOR.
    for _,size,start in segments:
        for byte in memoryview(raw)[start:start+size]:checksum^=byte
    if image[end-1]!=checksum:raise ValueError("safe1 application checksum mismatch")
    if _crc8266(raw)!=stored_crc:raise ValueError("safe1 SDK image CRC mismatch")

def compact(obj):
    return json.dumps(obj,ensure_ascii=True,separators=(",",":")).encode("ascii")

def strict_json(raw):
    def pairs(items):
        obj = {}
        for key,value in items:
            if key in obj: raise ValueError("duplicate JSON field")
            obj[key] = value
        return obj
    try: return json.loads(raw,object_pairs_hook=pairs)
    except (UnicodeError,json.JSONDecodeError,TypeError) as exc: raise ValueError("invalid JSON") from exc

def safe(value,limit):
    if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,"+str(limit-1)+"}",value) or ".." in value:
        raise ValueError("unsafe metadata component")

def ascii_version(value):
    if not isinstance(value,str) or not 1<=len(value)<=31 or any(ord(c)<32 or ord(c)>126 for c in value):raise ValueError("invalid ASCII version")

def validate(fields):
    if set(fields)!=FIELDS or fields["schema"]!=1 or type(fields["schema"]) is not int or fields["channel"]!="stable": raise ValueError("unsupported manifest contract")
    for name in ("sequence","size"):
        if type(fields[name]) is not int or not 0<fields[name]<=0xffffffff: raise ValueError("invalid uint32")
    ascii_version(fields["version"])
    for name,limit in (("profile",47),("tag",47),("artifact",95)): safe(fields[name],limit)
    if not fields["artifact"].endswith(".bin"): raise ValueError("program BIN required")
    for name,length in (("sha256",64),("image_signature",512)):
        if not isinstance(fields[name],str) or not re.fullmatch("[0-9a-f]{"+str(length)+"}",fields[name]): raise ValueError("invalid hash/signature")

def key_ok(key,private=False):
    expected = rsa.RSAPrivateKey if private else rsa.RSAPublicKey
    if not isinstance(key,expected) or key.key_size!=2048 or (key.public_key() if private else key).public_numbers().e!=65537: raise ValueError("RSA2048 exponent65537 required")

def check_image(image,fields,max_size=MAX_IMAGE):
    if not image or len(image)>max_size or image[0]!=0xe9: raise ValueError("invalid or oversized application BIN")
    if fields["sequence"] >= BRAND_SEQUENCE and (image.count(BRAND_PREFIX) != 1 or image.count(BRAND_RECORD) != 1):
        raise ValueError("missing or noncanonical brand record")
    expected=("INNOTECH_OTA_META_V1|seq=%d|version=%s|profile=%s|"%(fields["sequence"],fields["version"],fields["profile"])).encode("ascii")
    if image.count(MARKER)!=1 or expected not in image: raise ValueError("embedded build metadata mismatch")
    if fields["profile"]==SAFE1_PROFILE:_check_safe1_image(image)

def sign(image,fields,key,max_size=MAX_IMAGE):
    key_ok(key,True)
    obj=dict(fields,schema=1,channel="stable",size=len(image),sha256=hashlib.sha256(image).hexdigest(),image_signature="0"*512)
    validate(obj)
    check_image(image,obj,max_size)
    obj["image_signature"]=key.sign(image,padding.PKCS1v15(),hashes.SHA256()).hex()
    payload=compact(obj).decode("ascii")
    envelope=compact(dict(payload=payload,signature=key.sign(payload.encode("ascii"),padding.PKCS1v15(),hashes.SHA256()).hex()))
    if len(envelope)>4096: raise ValueError("oversized envelope")
    return envelope

def authenticate(envelope,key):
    key_ok(key)
    if not isinstance(envelope,bytes) or len(envelope)>4096: raise ValueError("oversized envelope")
    env=strict_json(envelope)
    if not isinstance(env,dict) or set(env)!={"payload","signature"} or not isinstance(env["payload"],str) or not isinstance(env["signature"],str) or not re.fullmatch("[0-9a-f]{512}",env["signature"]): raise ValueError("invalid envelope")
    try: key.verify(bytes.fromhex(env["signature"]),env["payload"].encode("utf-8"),padding.PKCS1v15(),hashes.SHA256())
    except InvalidSignature as exc: raise ValueError("manifest signature failed") from exc
    obj=strict_json(env["payload"])
    if not isinstance(obj,dict): raise ValueError("invalid payload")
    validate(obj)
    return obj

def verify(envelope,image,key,max_size=MAX_IMAGE):
    obj=authenticate(envelope,key)
    check_image(image,obj,max_size)
    if obj["size"]!=len(image) or obj["sha256"]!=hashlib.sha256(image).hexdigest(): raise ValueError("image length/hash mismatch")
    try: key.verify(bytes.fromhex(obj["image_signature"]),image,padding.PKCS1v15(),hashes.SHA256())
    except InvalidSignature as exc: raise ValueError("image signature failed") from exc
    return obj

def package(image_path,output,fields,key,max_size=MAX_IMAGE):
    image_path,output=Path(image_path),Path(output)
    if not image_path.is_file() or image_path.is_symlink() or image_path.suffix!=".bin": raise ValueError("explicit regular BIN required")
    if image_path.stat().st_size>max_size: raise ValueError("oversized BIN")
    image=image_path.read_bytes()
    envelope=sign(image,fields,key,max_size)
    verify(envelope,image,key.public_key(),max_size)
    output.mkdir(parents=True,exist_ok=False)
    (output/fields["artifact"]).write_bytes(image)
    (output/("manifest-"+fields["profile"]+".json")).write_bytes(envelope)
    return envelope

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=["package","verify"])
    parser.add_argument("--image",type=Path,required=True)
    parser.add_argument("--key",type=Path,required=True,help="existing private PEM for package; public PEM for verify")
    parser.add_argument("--manifest",type=Path)
    parser.add_argument("--output",type=Path)
    parser.add_argument("--sequence",type=int)
    for name in ("version","profile","tag","artifact"): parser.add_argument("--"+name)
    args=parser.parse_args()
    try:
        pem=args.key.read_bytes()
        if args.command=="verify":
            if not args.manifest: parser.error("--manifest required")
            verify(args.manifest.read_bytes(),args.image.read_bytes(),serialization.load_pem_public_key(pem))
        else:
            if not args.output or any(getattr(args,n) is None for n in ("sequence","version","profile","tag","artifact")): parser.error("package requires output and all build metadata")
            package(args.image,args.output,{n:getattr(args,n) for n in ("sequence","version","profile","tag","artifact")},serialization.load_pem_private_key(pem,password=None))
        print("Verified signed application package")
    except (ValueError,OSError): parser.exit(1,"OTA package rejected; check input, metadata, and key configuration.\n")

if __name__=="__main__": main()
