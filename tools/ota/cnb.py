"""CNB mirror adapter based on https://api.cnb.cool/swagger.json.
No signing or key generation. All external writes require explicit CLI --publish.
"""
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from . import release
from .configure import coordinate

class UnconfiguredStorageHost(ValueError):
    """Only a validated DNS hostname may reach the enrollment diagnostic."""
    def __init__(self,hostname):
        if not isinstance(hostname,str) or not 1<=len(hostname)<=253 or not hostname.isascii():raise ValueError("invalid diagnostic hostname")
        parts=hostname.split(".")
        if len(parts)<2 or not any(c.isalpha() for c in parts[-1]) or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",part) for part in parts):raise ValueError("invalid diagnostic hostname")
        self._hostname=hostname
        super().__init__("unconfigured storage hostname")

    @property
    def hostname(self):return self._hostname

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): return None

class Client:
    def __init__(self,repo,token,commitish,storage_hosts,*,api_origin="https://api.cnb.cool",public_origin="https://cnb.cool",test_loopback=False):
        coordinate(repo)
        if not token or any(ch in token for ch in "\r\n"):raise ValueError("missing/invalid CI token")
        if not commitish or len(commitish)>128 or any(ch in commitish for ch in "\r\n"):raise ValueError("missing target commitish")
        self.repo=repo;self.token=token;self.commitish=commitish
        self.api_origin=api_origin.rstrip("/");self.public_origin=public_origin.rstrip("/")
        self.test_loopback=test_loopback
        if not test_loopback and (self.api_origin!="https://api.cnb.cool" or self.public_origin!="https://cnb.cool"):raise ValueError("fixed CNB origins required")
        if test_loopback and any(urllib.parse.urlsplit(u).hostname!="127.0.0.1" for u in (api_origin,public_origin)):raise ValueError("test transport is loopback only")
        self.storage_hosts=set(storage_hosts)
        if not self.storage_hosts or any(not h or "/" in h or ":" in h or "*" in h for h in self.storage_hosts):raise ValueError("exact storage host allowlist required")
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        self.prefix="/"+repo+"/-/releases"

    def check_url(self,url,*,auth=False,storage=False):
        if not isinstance(url,str) or any(ord(c)<33 or ord(c)>126 for c in url) or "\\" in url or "#" in url:raise ValueError("unsafe raw URL")
        parsed=urllib.parse.urlsplit(url)
        if parsed.username or parsed.password or parsed.fragment or parsed.scheme!="https" and not (self.test_loopback and parsed.scheme=="http" and parsed.hostname=="127.0.0.1"):raise ValueError("unsafe URL")
        if not self.test_loopback and parsed.port not in (None,443):raise ValueError("unexpected HTTPS port")
        origin=parsed.scheme+"://"+parsed.netloc
        if auth:
            # Reject encodings altogether: no intermediate proxy may decode an
            # apparently confined URL into dot segments or path separators.
            segments=parsed.path.split("/")[1:]
            if "%" in parsed.path or not segments or any(not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]*",part) or part in (".","..") for part in segments):raise ValueError("noncanonical API path")
            if "?" in url and not parsed.query:raise ValueError("empty API query")
            if parsed.query and not (parsed.query=="ttl=0" and "/asset-upload-confirmation/" in parsed.path):raise ValueError("unexpected API query")
            if origin!=self.api_origin or not parsed.path.startswith(self.prefix+"/") and parsed.path!=self.prefix:raise ValueError("API origin/path mismatch")
        elif storage:
            if parsed.hostname not in self.storage_hosts:raise UnconfiguredStorageHost(parsed.hostname)
        elif origin!=self.public_origin and parsed.hostname not in self.storage_hosts:raise UnconfiguredStorageHost(parsed.hostname)
        return url

    def request(self,method,url,data=None,*,auth=False,storage=False,limit=65536,missing=False,redirects=0,accept=None):
        deadline=time.monotonic()+90
        for hop in range(redirects+1):
            if time.monotonic()>deadline:raise ValueError("CNB redirect-chain deadline exceeded")
            self.check_url(url,auth=auth,storage=storage)
            headers={"Accept":accept or ("application/vnd.cnb.api+json" if auth else "application/octet-stream")}
            if auth:headers["Authorization"]="Bearer "+self.token
            if data is not None:headers["Content-Type"]="application/octet-stream" if storage else "application/json"
            request=urllib.request.Request(url,data=data,headers=headers,method=method)
            try:response=self.opener.open(request,timeout=15)
            except urllib.error.HTTPError as exc:response=exc
            with response:
                status=response.status
                if status==404 and missing:return None
                if status in (301,302,303,307,308):
                    if auth or method!="GET" or hop==redirects:raise ValueError("redirect rejected")
                    target=response.headers.get("Location")
                    if not target:raise ValueError("missing redirect URL")
                    url=urllib.parse.urljoin(url,target)
                    continue
                if not 200<=status<300:raise ValueError("CNB HTTP operation failed")
                length=response.headers.get("Content-Length")
                if length is not None and (not length.isdigit() or int(length)>limit):raise ValueError("oversized response")
                output=bytearray()
                while True:
                    if time.monotonic()>deadline:raise ValueError("CNB operation deadline exceeded")
                    chunk=response.read1(min(65536,limit+1-len(output)))
                    if not chunk:break
                    output.extend(chunk)
                    if len(output)>limit:raise ValueError("oversized response")
                if length is not None and len(output)!=int(length):raise ValueError("truncated response")
                return bytes(output)
        raise ValueError("redirect limit")

    def api(self,method,path,obj=None,missing=False):
        raw=self.request(method,self.api_origin+path,release.compact(obj) if obj is not None else None,auth=True,missing=missing)
        if raw is None:return None
        return release.strict_json(raw) if raw else {}

    def by_tag(self,tag):return self.api("GET",self.prefix+"/tags/"+tag,missing=True)

    def ensure(self,tag):
        item=self.by_tag(tag)
        if item is None:item=self.api("POST",self.prefix,dict(tag_name=tag,target_commitish=self.commitish,name=tag,draft=False,prerelease=False,make_latest="false"))
        if not isinstance(item,dict) or item.get("tag_name")!=tag or item.get("draft") or item.get("prerelease") or not isinstance(item.get("id"),str):raise ValueError("invalid release response")
        release.safe(item["id"],128)
        return item

    def download(self,tag,name,limit,missing=False):
        return self.request("GET",self.public_origin+self.prefix+"/download/"+tag+"/"+name,limit=limit,missing=missing,redirects=3)

    def upload(self,item,name,data,overwrite=False,before_confirm=None):
        path=self.prefix+"/"+item["id"]+"/asset-upload-url"
        prepared=self.api("POST",path,dict(asset_name=name,size=len(data),overwrite=overwrite,ttl=0))
        if not isinstance(prepared,dict) or type(prepared.get("expires_in_sec")) is not int or prepared["expires_in_sec"]<=0:raise ValueError("invalid upload response")
        upload=prepared.get("upload_url");confirm=prepared.get("verify_url")
        if not isinstance(upload,str) or not isinstance(confirm,str):raise ValueError("missing upload URLs")
        self.check_url(upload,storage=True);self.check_url(confirm,auth=True)
        parsed=urllib.parse.urlsplit(confirm)
        expected=self.prefix+"/"+item["id"]+"/asset-upload-confirmation/"
        tail=parsed.path[len(expected):] if parsed.path.startswith(expected) else ""
        if not tail or len(tail.split("/"))<2 or parsed.query:raise ValueError("unexpected confirmation path")
        started=time.monotonic()
        self.request("PUT",upload,data,storage=True)
        if time.monotonic()-started>=prepared["expires_in_sec"]:raise ValueError("upload URL expired before confirmation")
        if before_confirm:before_confirm()
        self.request("POST",confirm+"?ttl=0",b"{}",auth=True)

def publish(directory,key,tag,client,authority):
    from .mirror import plan
    actions=plan(directory,key,tag)
    directory=Path(directory);name=actions[0]["artifact"];manifest=actions[2]["artifact"]
    image=(directory/name).read_bytes();envelope=(directory/manifest).read_bytes();candidate=release.authenticate(envelope,key)
    if tag=="ota-stable":raise ValueError("reserved stable tag")
    github_identity=authority(tag,manifest,envelope,key)
    stable=client.download("ota-stable",manifest,4096,missing=True)
    if stable is not None:
        previous=release.authenticate(stable,key)
        if previous["profile"]!=candidate["profile"] or previous["sequence"]>candidate["sequence"]:raise ValueError("stable downgrade/profile rejected")
        if previous["sequence"]==candidate["sequence"] and stable!=envelope:raise ValueError("sequence already used by different release")
    immutable=client.ensure(tag)
    for filename,data,limit in ((name,image,release.MAX_IMAGE),(manifest,envelope,4096)):
        existing=client.download(tag,filename,limit,missing=True)
        if existing is not None and existing!=data:raise ValueError("immutable version bytes differ")
        if existing is None:client.upload(immutable,filename,data,False)
        # A fresh anonymous full read, not upload status, authorizes advancement.
        if client.download(tag,filename,limit)!=data:raise ValueError("mirror bytes mismatch")
    # Re-read immediately before promotion; CI concurrency handles this project's writers.
    latest=client.download("ota-stable",manifest,4096,missing=True)
    if latest!=stable:raise ValueError("stable changed during mirror operation")
    if stable!=envelope:
        item=client.ensure("ota-stable")
        if authority(tag,manifest,envelope,key)!=github_identity:raise ValueError("GitHub Latest identity changed during mirroring")
        def still_current():
            if authority(tag,manifest,envelope,key)!=github_identity:raise ValueError("GitHub Latest changed before stable confirmation")
        client.upload(item,manifest,envelope,True,before_confirm=still_current)
        if client.download("ota-stable",manifest,4096)!=envelope:raise ValueError("stable bytes mismatch")
    return actions
