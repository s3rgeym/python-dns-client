from typing import Mapping
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

from ..client import DNSClient
from ..log import logger
from ..utils import ttl_lru_cache

DNS_CACHE_TTL = 300


# https://stackoverflow.com/a/57477670
class DNSClientAdapter(HTTPAdapter):
    def __init__(self, host: str, port: int | None) -> None:
        self.dns_client = DNSClient(host, port)
        super().__init__()

    @ttl_lru_cache(DNS_CACHE_TTL, maxsize=1024)
    def resolve(self, hostname: str) -> str:
        return self.dns_client.gethostaddr(hostname)

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: float | tuple[float, float] | tuple[float, None] | None = None,
        verify: bool | str = True,
        cert: bytes | str | tuple[bytes | str, bytes | str] | None = None,
        proxies: Mapping[str, str] | None = None,
    ) -> requests.Response:
        u = urlparse(request.url)
        resolved_ip = self.resolve(u.hostname)
        logger.debug("resolved ip: %s", resolved_ip)
        self.poolmanager.connection_pool_kw |= {
            "server_hostname": u.hostname,
            "assert_hostname": u.hostname,
        }
        request.url = request.url.replace(
            u.scheme + "://" + u.hostname,
            u.scheme
            + "://"
            + (resolved_ip, f"[{resolved_ip}]")[":" in resolved_ip],
        )
        logger.debug("request url: %s", request.url)
        request.headers["Host"] = u.hostname
        return super().send(request, stream, timeout, verify, cert, proxies)


class DNSClientSession(requests.Session):
    def __init__(self, host: str, port: int | None = None) -> None:
        super().__init__()
        # fix: AttributeError: 'DNSClientSession' object has no attribute 'adapters'
        a = DNSClientAdapter(host, port)
        self.mount("http://", a)
        self.mount("https://", a)
