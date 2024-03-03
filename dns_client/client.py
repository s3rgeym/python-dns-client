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
from .utils import split_hex


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


DNS_PORT = 53
DNS_OVER_TLS_PORT = 853


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

    def connect(self) -> None:
        try:
            logger.debug("try to connect %s#%d", self.host, self.port)
            if self.over_tls:
                # DNS Over TLS использует TCP
                self.sock = socket.socket(
                    self.address_family, socket.SOCK_STREAM
                )
                # context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                context = ssl.create_default_context()
                self.sock = context.wrap_socket(
                    self.sock,
                    server_hostname=self.host,
                )
            else:
                # socket.SOCK_DGRAM = UDP
                self.sock = socket.socket(
                    self.address_family, socket.SOCK_DGRAM
                )
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

    @property
    def is_udp(self) -> bool:
        return self.connected and self.sock.type == socket.SOCK_DGRAM

    @property
    def is_tcp(self) -> bool:
        return self.connected and self.sock.type == socket.SOCK_STREAM

    def send_data(self, data: bytes) -> int:
        # Подключаемся, если не были подключены
        if not self.connected:
            self.connect()
        if self.is_tcp:
            # 2 байта в начале TCP-пакета — длина
            data = int.to_bytes(len(data), 2) + data
        with self.lock:
            try:
                return self.sock.send(data)
            except SOCKET_ERRORS as ex:
                raise SocketError("socket write error") from ex

    def read_data(self) -> bytearray:
        with self.lock:
            try:
                buf = (
                    bytearray(int.from_bytes(self.sock.recv(2)))
                    if self.is_tcp
                    else bytearray(1024)
                )
                logger.debug("read buffer size: %d", len(buf))
                n = self.sock.recv_into(buf, len(buf))
                logger.debug("bytes recieved: %d", n)
                return buf
            except SOCKET_ERRORS as ex:
                raise SocketError("socket read error") from ex

    def read_packet(self) -> Packet:
        with self.lock:
            buf = self.read_data()
            return Packet.read_from(io.BytesIO(buf))

    def send_packet(self, packet: Packet) -> Packet:
        data = packet.to_bytes()

        # получение TXT у ya.ru
        # 1d cd | 01 00 | 00 01 00 00 00 00 00 00 | 02 79 61 02 72 75 00 | 00 | 10 | 00 | 01
        logger.debug("query raw data: %s", " ".join(split_hex(data)))

        with self.lock:
            n = self.send_data(data)
            logger.debug("bytes sent: %d", n)
            return self.read_packet()

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
