"""Generate public-only firmware build configuration; never creates keys."""
import argparse
import json
import re
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from . import release

def coordinate(repo):
    if not isinstance(repo,str) or len(repo)>=160 or ".." in repo or not 2<=len(repo.split("/"))<=8: raise ValueError("owner/repo required")
    for component in repo.split("/"): release.safe(component,100)
    return repo

def header(pem,github,cnb,sequence,version,profile):
    coordinate(github);coordinate(cnb)
    if len(github.split("/"))!=2: raise ValueError("GitHub owner/repo required")
    release.key_ok(serialization.load_pem_public_key(pem))
    if type(sequence) is not int or not 0<sequence<=0xffffffff: raise ValueError("invalid sequence")
    release.ascii_version(version);release.safe(profile,47)
    # Re-encode only a parsed public key; private material cannot enter generated file.
    public=serialization.load_pem_public_key(pem).public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    values=dict(OTA_GITHUB_REPO=github,OTA_CNB_REPO=cnb,OTA_PUBLIC_KEY=public,OTA_VERSION=version,OTA_PROFILE=profile)
    lines=["#pragma once","// Generated public-only OTA configuration."]
    lines += ["#define "+name+" "+json.dumps(value) for name,value in values.items()]
    lines += ["#define OTA_SEQUENCE "+str(sequence)]
    return "\n".join(lines)+"\n"

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-key",type=Path,required=True)
    parser.add_argument("--github-repo",required=True);parser.add_argument("--cnb-repo",required=True)
    parser.add_argument("--sequence",type=int,required=True);parser.add_argument("--version",required=True);parser.add_argument("--profile",required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    try:
        text=header(args.public_key.read_bytes(),args.github_repo,args.cnb_repo,args.sequence,args.version,args.profile)
        with args.output.open("x",encoding="ascii",newline="\n") as stream:stream.write(text)
    except (ValueError,OSError):parser.exit(1,"Public OTA configuration rejected.\n")

if __name__=="__main__":main()
