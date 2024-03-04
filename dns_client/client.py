import dataclasses
import functools
import io
import socket
import ssl
import threading
import time
import types
import typing

from .errors import ConnectionError, DNSError, SocketError
from .log import logger
from .protocol import Packet, Record, RecordType

DNS_PORT = 53
DNS_OVER_TLS_PORT = 853

MAX_PACKET_SIZE = (1 << 16) - 1

CONNECTION_ERRORS = (
    socket.herror,  # gethostaddr error
    socket.gaierror,  # getaddrinfo error
)


SOCKET_ERRORS = (socket.error, socket.timeout)


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


@dataclasses.dataclass
class DNSClient:
    host: str
    port: int | None = None
    _: dataclasses.KW_ONLY
    over_tls: bool = False
    timeout: float | None = None
    sock: socket.socket | None = None

    def __post_init__(self) -> None:
        if self.port is None:
            self.port = DNS_OVER_TLS_PORT if self.over_tls else DNS_PORT
        self.lock = threading.RLock()

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

    def get_udp_socket(self) -> socket.socket:
        return socket.socket(
            self.address_family,
            socket.SOCK_DGRAM,
        )

    def get_tcp_socket(self) -> socket.socket:
        sock = socket.socket(self.address_family, socket.SOCK_STREAM)
        # fast open как рекомендует спецификация
        sock.setsockopt(socket.SOL_TCP, socket.TCP_FASTOPEN, 5)
        # просим сервер не разрывать соединение (это его ни к чему не обязывает)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        context = ssl.create_default_context()
        return context.wrap_socket(sock, server_hostname=self.host)

    def connect(self) -> None:
        try:
            logger.debug("connect to %s#%d", self.host, self.port)
            self.sock = (
                self.get_tcp_socket()
                if self.over_tls
                else self.get_udp_socket()
            )
            self.sock.settimeout(self.timeout)
            self.sock.connect(self.address)
            logger.info("connection established: %s#%d", self.host, self.port)
        except CONNECTION_ERRORS as ex:
            self.sock = None
            raise ConnectionError() from ex

    @property
    def connected(self) -> bool:
        return not (self.sock is None or self.sock._closed)

    def disconnect(self) -> None:
        if not self.connected:
            return
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

    def write_socket(self, data: bytes) -> int:
        if not self.connected:
            self.connect()
        with self.lock:
            try:
                return self.sock.send(data)
            except SOCKET_ERRORS as ex:
                raise SocketError("socket write error") from ex

    def read_socket(self, buf: bytes | bytearray | memoryview) -> int:
        with self.lock:
            try:
                return self.sock.recv_into(buf)
            except SOCKET_ERRORS as ex:
                raise SocketError("socket read error")

    def send_packet(self, packet: Packet) -> Packet:
        data = packet.to_bytes()

        # получение TXT у ya.ru
        # 1d cd | 01 00 | 00 01 00 00 00 00 00 00 | 02 79 61 02 72 75 00 | 00 | 10 | 00 | 01
        logger.debug("query raw data: %s", data.hex(" ", 1))

        if self.over_tls:
            # https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
            # 2 байта в начале TCP-пакета — длина
            data = int.to_bytes(len(data), 2) + data

        with self.lock:
            while True:
                n = self.write_socket(data)
                logger.debug("bytes sent: %d", n)
                buf = bytearray(MAX_PACKET_SIZE)
                n = self.read_socket(buf)
                logger.debug("bytes recieved: %d", n)

                if n:
                    # ответы по TCP тоже содержат 2 байта с размероав в начале
                    buf = io.BytesIO(buf[2:] if self.over_tls else buf)
                    return Packet.read_from(buf)

                # если сервер разрывает соединение, то приходит пустой ответ
                logger.info("connection closed... reconnect")
                self.sock = None

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
