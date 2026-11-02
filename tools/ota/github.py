"""Bounded GitHub Latest reads; optional token confined to its exact API URL."""
import os
import urllib.parse
import urllib.request
from .cnb import Client,NoRedirect
from .configure import coordinate
from . import release

class GitHubHttpFailure(ValueError):
    """Safe diagnostic: no request/response values other than bounded status."""
    def __init__(self,stage,status):
        if stage not in ('github_latest','github_download') or type(status) is not int or not 100<=status<=599:
            raise ValueError("invalid GitHub HTTP diagnostic")
        super().__init__(stage+"/status"+str(status))

class Authority(Client):
    def __init__(self,repo):
        coordinate(repo)
        if len(repo.split("/"))!=2:raise ValueError("GitHub owner/repo required")
        self.repo=repo
        self.latest_url="https://api.github.com/repos/"+repo+"/releases/latest"
        self.token=os.environ.get("GH_TOKEN","")
        if any(ord(c)<33 or ord(c)>126 for c in self.token):raise ValueError("invalid GitHub token")
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())

    def check_url(self,url,*,auth=False,storage=False):
        if storage or not isinstance(url,str) or any(ord(c)<33 or ord(c)>126 for c in url) or "\\" in url:raise ValueError("unsafe GitHub request")
        parsed=urllib.parse.urlsplit(url)
        if parsed.scheme!="https" or parsed.username or parsed.password or parsed.fragment or parsed.port not in (None,443):raise ValueError("unsafe GitHub URL")
        if parsed.hostname not in ("api.github.com","github.com","release-assets.githubusercontent.com","objects.githubusercontent.com"):raise ValueError("unconfigured GitHub download host")
        if auth and (not self.token or url!=self.latest_url):raise ValueError("GitHub auth endpoint mismatch")
        return url

    def http_failure(self,url,status,**context):
        return GitHubHttpFailure("github_latest" if url==self.latest_url else "github_download",status)

    def request(self,method,url,data=None,**kwargs):
        if kwargs.get("auth") and (method!="GET" or data is not None):raise ValueError("GitHub auth requires read-only request")
        return super().request(method,url,data,**kwargs)

    def latest(self):
        raw=self.request("GET",self.latest_url,auth=bool(self.token),limit=65536,accept="application/vnd.github+json")
        item=release.strict_json(raw)
        if not isinstance(item,dict) or type(item.get("id")) is not int or not isinstance(item.get("tag_name"),str) or item.get("draft") or item.get("prerelease"):raise ValueError("invalid GitHub latest release")
        release.safe(item["tag_name"],47)
        return (item["id"],item["tag_name"])

    def __call__(self,tag,manifest,envelope,key):
        identity=self.latest()
        if identity[1]!=tag:raise ValueError("event is not GitHub Latest")
        raw=self.request("GET","https://github.com/"+self.repo+"/releases/latest/download/"+manifest,limit=4096,redirects=3)
        release.authenticate(raw,key)
        if raw!=envelope or self.latest()!=identity:raise ValueError("GitHub latest manifest/identity changed")
        return identity
