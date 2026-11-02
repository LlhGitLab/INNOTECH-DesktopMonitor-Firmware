"""Anonymous bounded reads of GitHub's authoritative Latest release."""
import urllib.parse
import urllib.request
from .cnb import Client,NoRedirect
from .configure import coordinate
from . import release

class Authority(Client):
    def __init__(self,repo):
        coordinate(repo)
        if len(repo.split("/"))!=2:raise ValueError("GitHub owner/repo required")
        self.repo=repo
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())

    def check_url(self,url,*,auth=False,storage=False):
        if auth or storage or not isinstance(url,str) or any(ord(c)<33 or ord(c)>126 for c in url) or "\\" in url:raise ValueError("unsafe GitHub request")
        parsed=urllib.parse.urlsplit(url)
        if parsed.scheme!="https" or parsed.username or parsed.password or parsed.fragment or parsed.port not in (None,443):raise ValueError("unsafe GitHub URL")
        if parsed.hostname not in ("api.github.com","github.com","release-assets.githubusercontent.com","objects.githubusercontent.com"):raise ValueError("unconfigured GitHub download host")
        return url

    def latest(self):
        raw=self.request("GET","https://api.github.com/repos/"+self.repo+"/releases/latest",limit=65536,accept="application/vnd.github+json")
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
