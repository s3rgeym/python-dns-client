import dataclasses
import functools
import io
import socket
import threading
import time
import types
import typing

from .errors import ConnectionError, DNSError, SocketError
from .log import logger
from .protocol import Packet, Record, RecordType
from .utils import split_hex

DNS_PORT = 53


def timeit(fn: typing.Callable) -> typing.Callable:
    @functools.wraps(fn)
    def timed(*args: typing.Any, **kwargs: typing.Any) -> typing.Any:
        try:
            dt = -time.monotonic()
            return fn(*args, **kwargs)
        finally:
            dt += time.monotonic()
            logger.debug("function %s tooks %.3fs", fn.__name__, dt)

    return timed


CONNECTION_ERRORS = (
    socket.herror,  # gethostaddr error
    socket.gaierror,  # getaddrinfo error
)


SOCKET_ERRORS = (socket.error, socket.timeout)


@dataclasses.dataclass
class DNSClient:
    host: str
    port: int | None = None
    timeout: float | None = None
    sock: socket.socket | None = None

    def __post_init__(self) -> None:
        self.port = self.port or DNS_PORT
        self._lock = threading.RLock()

    @property
    def address(self) -> tuple[str, int]:
        return self.host, self.port

    @functools.cached_property
    def address_family(self) -> socket.AddressFamily:
        try:
            socket.inet_pton(socket.AF_INET6, self.host)
            return socket.AF_INET6
        except (socket.error, ValueError):
            return socket.AF_INET

    def connect(self) -> None:
        try:
            # socket.SOCK_DGRAM = UDP
            self.sock = socket.socket(self.address_family, socket.SOCK_DGRAM)
            # TODO: к сожалению модуль ssl не поддерживает udp-сокеты
            # if self.ssl:
            #     context = ssl.create_default_context()
            #     self.sock = context.wrap_socket(
            #         self.sock, server_hostname=self.host
            #     )
            self.sock.connect(self.address)
            self.sock.settimeout(self.timeout)
        except CONNECTION_ERRORS as ex:
            self.sock = None
            raise ConnectionError() from ex
        logger.info("connection established: %s#%d", self.host, self.port)

    @property
    def connected(self) -> bool:
        return self.sock is not None

    def disconnect(self) -> None:
        if self.connected:
            self.sock.close()
            self.sock = None
            logger.info("disconnected: %s#%d", self.host, self.port)

    def __enter__(self) -> typing.Self:
        self.connect()
        return self

    def __exit__(
        self,
        exc_qtype: typing.Type[BaseException],
        exc_val: BaseException,
        exc_tb: types.TracebackType | None,
    ) -> None:
        self.disconnect()

    def read_packet(self) -> Packet:
        with self._lock:
            try:
                b = bytearray(4096)
                n = self.sock.recv_into(b, len(b))
                logger.debug("bytes recieved: %d", n)
                return Packet.read_from(io.BytesIO(b))
            except SOCKET_ERRORS as ex:
                raise SocketError("socket read error") from ex

    def send_packet(self, packet: Packet) -> Packet:
        # Подключаемся, если не были подключены
        if not self.connected:
            self.connect()

        data = packet.to_bytes()

        assert len(data) > 12

        # получение TXT у ya.ru
        # 1d cd | 01 00 | 00 01 00 00 00 00 00 00 | 02 79 61 02 72 75 00 | 00 | 10 | 00 | 01
        logger.debug("raw query data: %s", " ".join(split_hex(data)))

        with self._lock:
            try:
                n = self.sock.send(data)
                logger.debug("bytes sent: %d", n)
                return self.read_packet()
            except SOCKET_ERRORS as ex:
                raise SocketError("socket write error") from ex

    def get_query_response(
        self,
        name: str,
        qtype: RecordType | list[RecordType] = RecordType.A,
    ) -> Packet:
        """sends query and returns response"""
        query = Packet.build_query(name, qtype)
        logger.debug(query)
        # assert query.header.flags == 0x120
        response = self.send_packet(query)
        logger.debug(response)
        assert response.is_response
        assert query.header.id == response.header.id
        assert query.question == response.question
        return response

    @timeit
    def query(
        self,
        name: str,
        qtype: RecordType | list[RecordType] = RecordType.A,
    ) -> list[Record]:
        """sends query and returns list of records, raises DNSError if response code != 0x00"""
        response = self.get_query_response(name, qtype=qtype)
        DNSError.raise_for_response(response)
        return response.records[:]

    def gethostaddr(self, s: str) -> str | None:
        records = self.query(s) or self.query(s, RecordType.AAAA)
        return records[0].value if records else None

    def get_name_servers(self, s: str) -> list[str]:
        return [x.value for x in self.query(s, RecordType.NS)]

    def get_mail_servers(self, s: str) -> list[tuple[int, str]]:
        return [x.value for x in self.query(s, RecordType.MX)]

    def get_txt_records(self, s: str) -> list[str]:
        return [x.value for x in self.query(s, RecordType.TXT)]

    def get_all_records(self, s: str) -> list[tuple[str, typing.Any]]:
        rv = []
        for t in (
            RecordType.A,
            RecordType.AAAA,
            RecordType.CNAME,
            RecordType.MX,
            RecordType.NS,
            RecordType.TXT,
        ):
            rv += [(r.qtype.name, r.value) for r in self.query(s, t)]
        return rv
