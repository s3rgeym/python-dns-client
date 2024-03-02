from functools import lru_cache
from urllib.parse import urlparse

# я ненавижу requests, он написан так хуево, что ломает VSCode
import requests

from ..client import DNSClient
from ..log import logger


# https://stackoverflow.com/a/57477670
class DNSClientAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, dns_client: DNSClient) -> None:
        self.dns_client = dns_client
        super().__init__()

    # не дрочим резолвер на каждый запрос
    @lru_cache(maxsize=1024)
    def resolve(self, hostname: str) -> str | None:
        return self.dns_client.gethostaddr(hostname)

    def send(self, request, **kwargs):
        result = urlparse(request.url)
        resolved_ip = self.resolve(result.hostname)
        logger.debug("resolved %s => %s", result.hostname, resolved_ip)

        connection_pool_kw = self.poolmanager.connection_pool_kw
        if result.scheme in ("http", "https") and resolved_ip:
            connection_pool_kw |= {
                "server_hostname": result.hostname,
                "assert_hostname": result.hostname,
            }

            request.url = request.url.replace(
                result.scheme + "://" + result.hostname,
                result.scheme + "://" + resolved_ip,
            )

            logger.debug("modified request url: %s", request.url)
            request.headers["Host"] = result.hostname
        else:
            connection_pool_kw.pop("server_hostname", None)
            connection_pool_kw.pop("assert_hostname", None)

        logger.debug(connection_pool_kw)
        return super().send(request, **kwargs)


class DNSClientSession(requests.Session):
    def __init__(self, host: str, port: int | None = None) -> None:
        super().__init__()
        # fix: AttributeError: 'DNSClientSession' object has no attribute 'adapters'
        self.dns_client = DNSClient(host, port)
        self.mount("http://", DNSClientAdapter(self.dns_client))
        self.mount("https://", DNSClientAdapter(self.dns_client))
