"""Verify a dedicated downloaded release package and print an offline CNB mirror plan.
Real publishing is explicit and requires CI environment configuration.
"""
import argparse
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from . import release
from .cnb import UnconfiguredStorageHost,CnbHttpFailure,CnbValidationFailure,CnbApiPathRejected
from .github import GitHubHttpFailure

def plan(directory,key,tag):
    directory=Path(directory)
    if not directory.is_dir() or directory.is_symlink(): raise ValueError("dedicated package directory required")
    manifests=list(directory.glob("manifest-*.json"))
    if len(manifests)!=1: raise ValueError("exactly one profile manifest required")
    manifest=manifests[0]
    if manifest.is_symlink() or manifest.stat().st_size>4096: raise ValueError("invalid manifest")
    envelope=manifest.read_bytes()
    # Untrusted fields select only a safe basename; full authentication follows.
    env=release.strict_json(envelope)
    obj=release.strict_json(env["payload"])
    release.validate(obj)
    artifact=directory/obj["artifact"]
    if set(p.name for p in directory.iterdir())!={manifest.name,obj["artifact"]} or any(p.is_symlink() or not p.is_file() for p in directory.iterdir()): raise ValueError("package contains non-allowlisted files")
    if artifact.stat().st_size>release.MAX_IMAGE: raise ValueError("oversized image")
    release.verify(envelope,artifact.read_bytes(),key)
    if obj["tag"]!=tag or manifest.name!="manifest-"+obj["profile"]+".json": raise ValueError("release tag/profile mismatch")
    return [dict(phase="immutable",tag=tag,artifact=obj["artifact"],sha256=obj["sha256"]),dict(phase="verify-download",size=obj["size"],sha256=obj["sha256"]),dict(phase="stable-manifest",tag="ota-stable",artifact=manifest.name)]

def generic_failure_diagnostic(error):
    """Only a trusted deepest module's static basename/line and fixed type.

    Never format exception values, traceback paths, locals, or caller input.
    Unrecognized types or frames retain the existing generic diagnostic.
    """
    fallback="Mirror input rejected.\n"
    types={ValueError:"ValueError",OSError:"OSError",KeyError:"KeyError",TypeError:"TypeError"}
    kind=types.get(type(error))
    if kind is None:return fallback
    trace=error.__traceback__
    if trace is None:return fallback
    while trace.tb_next is not None:trace=trace.tb_next
    frame=trace.tb_frame
    owning=Path(__file__).resolve().parent
    allowed=("mirror.py","cnb.py","github.py","configure.py","release.py")
    try:
        filename=Path(frame.f_code.co_filename).resolve()
        modulefile=frame.f_globals.get("__file__")
        if type(modulefile) is not str:return fallback
        modulefile=Path(modulefile).resolve()
        for basename in allowed:
            expected=owning/basename
            name=frame.f_globals.get("__name__")
            module_owned=(name=="tools.ota."+basename[:-3] or
                          (basename=="mirror.py" and name=="__main__" and frame.f_globals is globals()))
            if filename==expected and modulefile==expected and module_owned and type(trace.tb_lineno) is int and trace.tb_lineno>0:
                return "Mirror input rejected: "+basename+":"+str(trace.tb_lineno)+"/"+kind+".\n"
    except (OSError,ValueError,TypeError):
        pass
    return fallback

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package",type=Path,required=True)
    parser.add_argument("--public-key",type=Path,required=True)
    parser.add_argument("--tag",required=True)
    parser.add_argument("--publish",action="store_true")
    args=parser.parse_args()
    try:
        actions=plan(args.package,serialization.load_pem_public_key(args.public_key.read_bytes()),args.tag)
        if args.publish:
            from .cnb import Client,publish
            if os.environ.get("CI")!="true" or os.environ.get("OTA_MIRROR_ENABLED")!="true":raise ValueError("explicit protected CI publishing configuration required")
            client=Client(os.environ.get("CNB_REPO",""),os.environ.get("CNB_TOKEN",""),os.environ.get("CNB_TARGET_COMMITISH",""),os.environ.get("CNB_STORAGE_HOSTS","").split(","))
            from .github import Authority
            publish(args.package,serialization.load_pem_public_key(args.public_key.read_bytes()),args.tag,client,Authority(os.environ.get("GH_REPO","")))
            print("Verified CNB version files and stable manifest")
            return
        print(json.dumps(dict(mode="dry-run",actions=actions),indent=2))
    except CnbApiPathRejected as exc: parser.exit(1,"CNB API path rejected: "+str(exc)+"\n")
    except CnbHttpFailure as exc: parser.exit(1,"CNB mirror failed: "+str(exc)+"\n")
    except CnbValidationFailure as exc: parser.exit(1,"CNB mirror rejected: "+str(exc)+"\n")
    except GitHubHttpFailure as exc: parser.exit(1,"GitHub authority failed: "+str(exc)+"\n")
    except UnconfiguredStorageHost as exc: parser.exit(2,"CNB_STORAGE_HOSTS requires: "+exc.hostname+"\n")
    except (ValueError,OSError,KeyError,TypeError) as exc: parser.exit(1,generic_failure_diagnostic(exc))

if __name__=="__main__": main()
