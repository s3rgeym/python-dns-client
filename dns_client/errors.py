from .protocol import Packet, ResponseCode


class Error(Exception):
    message: str = "An unexpected error has occurred"

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.message
        super().__init__(self.message)


class ConnectionError(Error):
    message = "Connection error"


class SocketError(Error):
    pass


class DNSError(Error):
    def __init__(self, response: Packet) -> None:
        self.response = response
        super().__init__(
            f"dns server returns bad response code: 0x{self.error_code:02X}"
        )

    @property
    def error_code(self) -> ResponseCode:
        return self.response.header.rcode

    @classmethod
    def raise_for_response(cls, response: Packet) -> None:
        if response.response_code:
            raise cls(response)
