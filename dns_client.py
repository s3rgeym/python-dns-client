# !/usr/bin/env python
# Useful links:
# https://www.geeksforgeeks.org/dns-message-format/
# https://levelup.gitconnected.com/dns-response-in-java-a6298e3cc7d9
# https://copyprogramming.com/howto/how-to-query-dns-records-using-python
# https://implement-dns.wizardzines.com/book/part_1
from __future__ import annotations

import dataclasses
import functools
import io
import logging
import operator
import secrets
import socket
import struct
import threading
import time
import types
import typing
from enum import IntEnum

__author__ = "Sergey M"
__version__ = "0.1.1"


logger = logging.getLogger(__name__)

__all__: tuple[str, ...] = (
    "DNSBadResponse",
    "DNSClient",
    "DNSError",
    "Header",
    "Packet",
    "Question",
    "Record",
    "RecordClass",
    "RecordType",
)


# https://github.com/Habbie/hello-dns/blob/master/tdns/dns-storage.hh#L73
class RecordType(IntEnum):
    UNKNOWN = -1
    EMPTY = 0
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    NAPTR = 35
    DS = 43
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    NSEC3 = 50
    OPT = 41
    IXFR = 251
    AXFR = 252
    ANY = 255
    CAA = 257

    @classmethod
    def _missing_(cls, value: typing.Any) -> RecordType:
        return cls.UNKNOWN


# https://github.com/Habbie/hello-dns/blob/master/tdns/dns-storage.hh#L85
# https://github.com/indented-automation/Indented.Net.Dns/blob/main/Indented.Net.Dns/enum/RecordClass.ps1
class RecordClass(IntEnum):
    EMPTY = 0
    IN = 1  # INternet
    CH = 3  # CHaos
    HS = 4
    NONE = 254
    ANY = 256


T = typing.TypeVar("T")


class RawPacketHandler:
    def parse(self, buf: typing.BinaryIO) -> None:
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        raise NotImplementedError

    @classmethod
    def from_buffer(cls: typing.Type[T], buf: typing.BinaryIO) -> T:
        o = cls()
        o.parse(buf)
        return o


# ! — big-endian, используемый как стандарт при передаче по сети (все компьютеры little-endian, если че)
HEADER_FORMAT = struct.Struct("!6H")


# https://nightlies.apache.org/directory/apacheds/2.0.0.AM26/apidocs/org/apache/directory/server/dns/messages/OpCode.html
class OpCode(IntEnum):
    QUERY = 0
    INVERSE = 1  # Inverse Query (OBSOLETE). See rfc3425.
    STATUS = 2
    # reserved


# https://powerdns.org/hello-dns/tdns/codedocs/html/dns-storage_8hh.html
class ResponseCode(IntEnum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5
    NOTAUTH = 9
    BADVERS = 16


# байтоебство мне не по нраву, а поэтому обернем все в классы
@dataclasses.dataclass
class BitsReader:
    """
    read bits from value

    Имеется число, представляющее флаги длиною в 16-бит:

    >>> f"{0x8180:016b}"
    '1000000110000000'

    Чтобы получить первый бит, нужно добить его нулями слева на
    length - count - offset:

    >>> f"{0x8180>>15:016b}"
    '0000000000000001'

    Где, offset >= 0, увеличивается итеративно, а count — количество бит, которое
    нужно прочитать.

    Допустим, нужно получить:

        100000[011]0000000

    Это значение начинается на смещении 6, начиная с 0, и имеет длину 3 бита:

    >>> f"{0x8180>>16-3-6:016b}"
    '0000000100000011'

    Но это еще не само значение. Чтобы его получить, надо к результату применить маску 0b111:

    >>> f"{(0x8180>>16-3-6)&0b111:016b}"
    '0000000000000011'

    Маска имеет ту же длину, что и искомое и заполняется единицами.

    Её можно получить так:

    >>> f"{(1<<3)-1:016b}"
    '0000000000000111'

    In [3]: reader = BitsReader(0x8180, 16)

    In [4]: f'{reader.value:016b}'
    Out[4]: '1000000110000000'

    In [5]: reader.read()
    Out[5]: 1

    In [6]: reader.read()
    Out[6]: 0

    ...

    In [12]: reader.read()
    Out[12]: 1

    In [13]: reader.read()
    Out[13]: 1

    In [14]: reader.read()
    Out[14]: 0

    In [15]: reader
    Out[15]: BitsReader(value=33152, length=16)

    In [18]: reader.offset = 6

    In [19]: f"{reader.read(3):016b}"
    Out[19]: '0000000000000011'
    """

    value: int
    length: int
    offset: int = dataclasses.field(init=0, repr=0, default=0)

    def read(self, n: int = 1) -> int:
        """read n bits from value"""
        assert n >= 1
        mask = (1 << n) - 1
        shift = self.length - n - self.offset
        try:
            # ValueError: negative shift n
            return (self.value >> shift) & mask
        finally:
            self.offset += n

    def read_bool(self) -> bool:
        """read 1 bit as bool"""
        return self.read() > 0

    read_flag = read_bool

    def seek(self, offset: int = 0) -> None:
        self.offset = offset


# В этом случае без классов и невозможно, т.к. в питоне нельзя передавать
# простые типы по ссылке как в PHP
@dataclasses.dataclass
class BitsWriter:
    """set bits for result"""

    length: int
    offset: int = dataclasses.field(init=0, repr=0, default=0)
    result: int = dataclasses.field(init=0, repr=0, default=0)

    def write(self, data: int | bool, n: int = 1) -> None:
        """set n bits from data at current offset"""
        assert n >= 1
        mask = (1 << n) - 1
        shift = self.length - n - self.offset
        # можно еще предварительно обнулять флаги
        self.result |= (data & mask) << shift
        self.offset += n


# Здесь описаны все поля заголовка: https://habr.com/ru/sandbox/112582/
# http://images.slideplayer.com/18/5705521/slides/slide_16.jpg
# # https://github.com/lun-4/zigdig/blob/master/src/packet.zig
@dataclasses.dataclass
class Header(RawPacketHandler):
    """Packet Header"""

    # id: int = dataclasses.field(
    #     default_factory=lambda: secrets.randbits(16)
    # )
    id: int = 0  # 2 bytes

    # https://www.oreilly.com/api/v2/epubs/9781789349863/files/assets/346de5c8-e0a1-4694-bee3-2ffd68761f09.png
    # https://learn.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_header
    # устанавливаются через flags
    response: bool = False  # 0. QR: query=0
    opcode: OpCode = OpCode.QUERY  # 4 bits (!bytes)
    authoritative_record: bool = False  # AA
    truncated: bool = False  # TC
    recursion_desired: bool = False  # RD
    recursion_available: bool = False  # RA
    reserved: typing.Literal[0] = 0  # Z (3 bits)
    rcode: ResponseCode = ResponseCode.NOERROR  # response code (4 bits)
    # 2 bytes each
    num_questions: int = 0
    num_records: int = 0
    num_authorities: int = 0
    num_additionals: int = 0

    _: dataclasses.KW_ONLY

    # это уже крякерство: у нас есть одноименный setter, который нужно дергать,
    # если передан аргумент `flags`
    flags: dataclasses.InitVar[int]

    # если `flags` не передать в аргументах, то будет передан объект `property`
    def __post_init__(self, flags: int | property) -> None:
        if isinstance(flags, int):
            self.flags = flags

    # Flags: 0x8180 Standard query response, No error
    # 1... .... .... .... = Response: Message is a response
    # .000 0... .... .... = Opcode: Standard query (0)
    # .... .0.. .... .... = Authoritative: Server is not an authority for domain
    # .... ..0. .... .... = Truncated: Message is not truncated
    # .... ...1 .... .... = Recursion desired: Do query recursively
    # .... .... 1... .... = Recursion available: Server can do recursive queries
    # .... .... .0.. .... = Z: reserved (0)
    # .... .... ..0. .... = Record authenticated: Record/authority portion was not authenticated by the server
    # .... .... ...0 .... = Non-authenticated data: Unacceptable
    # .... .... .... 0000 = Reply code: No error (0)

    # С BitsReader/BitsWriter я идею подсмотрел в библиотеке на каком-то функциональном языке
    # Очень изящно смотрится
    @property
    def flags(self) -> int:
        writer = BitsWriter(16)
        writer.write(self.response)
        writer.write(self.opcode, 4)
        writer.write(self.authoritative_record)
        writer.write(self.truncated)
        writer.write(self.recursion_desired)
        writer.write(self.recursion_available)
        writer.write(self.reserved, 3)
        writer.write(self.rcode, 4)
        logger.debug(f"get header flags: {writer.result:016b}")
        return writer.result

    @flags.setter
    def flags(self, v: int) -> None:
        logger.debug(f"set header flags: {v:016b}")
        reader = BitsReader(v, 16)
        self.response = reader.read_bool()
        self.opcode = OpCode(reader.read(4))
        self.authoritative_record = reader.read_bool()
        self.truncated = reader.read_bool()
        self.recursion_desired = reader.read_bool()
        self.recursion_available = reader.read_bool()
        self.reserved = reader.read(3)
        self.rcode = ResponseCode(reader.read(4))

    def to_bytes(self) -> bytes:
        return HEADER_FORMAT.pack(
            self.id,
            self.flags,
            self.num_questions,
            self.num_records,
            self.num_authorities,
            self.num_additionals,
        )

    def parse(self, buf: typing.BinaryIO) -> None:
        (
            self.id,
            self.flags,
            self.num_questions,
            self.num_records,
            self.num_authorities,
            self.num_additionals,
        ) = HEADER_FORMAT.unpack(buf.read(12))


def encode_name(s: str) -> bytes:
    """Кодирует имя. Имя хоста разбивается на сегменты по точке, каждому
    сегменту прешествует его длина = 1 байт, в конце всегда 0x00"""
    rv = b""
    for p in s.rstrip(".").encode().split(b"."):
        rv += len(p).to_bytes() + p
    return rv + b"\0"


def read_name(buf: typing.BinaryIO) -> str:
    rv = []
    while (length := int.from_bytes(buf.read(1))) > 0:
        # сжатые данные
        if length & 0xC0:
            # length = ((length & 0x3F) << 8) | *p;
            length = ((length & 0x3F) << 8) | int.from_bytes(buf.read(1))
            cur_pos = buf.tell()
            buf.seek(length)
            rv.append(read_name(buf))
            buf.seek(cur_pos)
            break
        rv.append(buf.read(length).decode())
    return ".".join(rv)


@dataclasses.dataclass
class Question(RawPacketHandler):
    """Query Question"""

    name: str | None = None
    qtype: RecordType = RecordType.EMPTY
    qclass: RecordClass = RecordClass.EMPTY

    def to_bytes(self) -> bytes:
        return (
            encode_name(self.name)
            + self.qtype.to_bytes(2)
            + self.qclass.to_bytes(2)
        )

    def parse(self, buf: typing.BinaryIO) -> None:
        self.name = read_name(buf)
        self.qtype = RecordType(
            int.from_bytes(
                buf.read(2),
            ),
        )
        self.qclass = RecordClass(
            int.from_bytes(
                buf.read(2),
            ),
        )


# https://implement-dns.wizardzines.com/book/part_2
# https://github.com/cmol/dnsmessage/blob/main/lib/dnsmessage/resource_record.rb
@dataclasses.dataclass
class Record(RawPacketHandler):
    """Response Record"""

    name: str | None = None
    qtype: int = RecordType.EMPTY
    qclass: int = RecordClass.EMPTY
    ttl: int = 0
    value: typing.Any = None

    def _parse_value(self, buf: typing.BinaryIO) -> typing.Any:
        # https://gist.github.com/bohwaz/ddc61c4f7e031c3221a89981e70b830c#file-dns_get_record_from-php-L140
        data_len = int.from_bytes(buf.read(2))
        match self.qtype:
            case RecordType.A:
                return socket.inet_ntoa(buf.read(data_len))
            case RecordType.AAAA:
                return socket.inet_ntop(socket.AF_INET6, buf.read(data_len))
            case RecordType.MX:
                pri = int.from_bytes(buf.read(2))  # priority
                return pri, read_name(buf)
            case RecordType.CNAME | RecordType.NS | RecordType.PTR:
                return read_name(buf)
            case RecordType.TXT:
                # https://en.m.wikipedia.org/wiki/TXT_record
                # первый байт - это длина текстовой записи
                return buf.read(data_len)[1:].decode()
            case RecordType.EMPTY:
                raise ValueError()
            case _:
                return buf.read(data_len)

    def parse(self, buf: typing.BinaryIO) -> None:
        self.name = read_name(buf)
        self.qtype = RecordType(
            int.from_bytes(
                buf.read(2),
            ),
        )
        self.qclass = RecordClass(
            int.from_bytes(
                buf.read(2),
            ),
        )
        self.ttl = int.from_bytes(buf.read(4))
        self.value = self._parse_value(buf)


class DNSError(Exception):
    pass


class DNSBadResponse(DNSError):
    def __init__(self, response: Packet) -> None:
        self.response = response
        super().__init__(
            f"dns server returns bad response code: 0x{self.response.response_code:02X}"
        )

    @classmethod
    def raise_for_response(cls, response: Packet) -> None:
        if response.response_code:
            raise cls(response)


def isiterable(v: typing.Any) -> bool:
    return isinstance(v, typing.Sequence) and not isinstance(v, (str, bytes))


@dataclasses.dataclass
class Packet(RawPacketHandler):
    """Query or Response Packet"""

    header: Header | None = None
    questions: list[Question] = dataclasses.field(default_factory=list)
    records: list[Record] = dataclasses.field(default_factory=list)
    # TODO: additionals and etc

    def parse(self, buf: io.BinaryIO) -> None:
        self.header = Header.from_buffer(buf)
        self.questions = [
            Question.from_buffer(buf) for _ in range(self.header.num_questions)
        ]
        self.records = [
            Record.from_buffer(buf) for _ in range(self.header.num_records)
        ]

    def to_bytes(self) -> bytes:
        to_bytes = operator.methodcaller("to_bytes")
        return b"".join(
            [
                self.header.to_bytes(),
                *map(to_bytes, self.questions),
                *map(to_bytes, self.records),
            ]
        )

    @property
    def response_code(self) -> ResponseCode:
        return self.header.rcode

    @property
    def is_response(self) -> bool:
        return self.header.response

    @property
    def is_query(self) -> bool:
        return not self.is_response

    @property
    def question(self) -> Question:
        return self.questions[0]

    @classmethod
    def build_query(
        cls: typing.Type[Packet],
        qname: str,
        qtype: RecordType | list[RecordType] = RecordType.A,
        /,
    ) -> Packet:
        # эти флаги устанавливает dig
        # Flags: 0x0120 Standard query
        # 0... .... .... .... = Response: Message is a query
        # .000 0... .... .... = Opcode: Standard query (0)
        # .... ..0. .... .... = Truncated: Message is not truncated
        # .... ...1 .... .... = Recursion desired: Do query recursively
        # .... .... .0.. .... = Z: reserved (0)
        # .... .... ..1. .... = AD bit: Set
        # .... .... ...0 .... = Non-authenticated data: Unacceptable

        questions = [
            Question(qname, typ, qclass=RecordClass.IN)
            for typ in (qtype if isiterable(qtype) else [qtype])
        ]

        if len(questions) > 1:
            logger.warning("most servers don't support multiple questions")

        return cls(
            header=Header(
                id=secrets.randbits(16),
                num_questions=len(questions),
                flags=0x120,
            ),
            questions=questions,
        )


def split_hex(b: bytes, n: int = 2) -> list[str]:
    return (h := b.hex()) and [h[i : i + n] for i in range(0, len(h), n)]


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
    resolver_host: str = "8.8.8.8"
    resolver_port: int = 53
    sock: socket.socket | None = None

    def __post_init__(self) -> None:
        self._lock = threading.RLock()

    @property
    def resolver_address(self) -> tuple[str, int]:
        return self.resolver_host, self.resolver_port

    def connect(self) -> None:
        try:
            # socket.SOCK_DGRAM = UDP
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # TODO: к сожалению модуль ssl не поддерживает udp-сокеты
            # if self.ssl:
            #     context = ssl.create_default_context()
            #     self.sock = context.wrap_socket(
            #         self.sock, server_hostname=self.resolver_host
            #     )

            self.sock.connect(self.resolver_address)
        except:
            self.sock = None
            raise

    @property
    def connected(self) -> bool:
        return self.sock is not None

    def disconnect(self) -> None:
        if self.connected:
            self.sock.close()
            self.sock = None

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
            b = bytearray(4096)
            self.sock.recv_into(b, len(b))
            return Packet.from_buffer(io.BytesIO(b))

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
            self.sock.send(data)
            return self.read_packet()

    def get_response_query(
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
        response.header.flags
        assert query.header.id == response.header.id
        assert query.question == response.question
        return response

    @timeit
    def query(
        self,
        name: str,
        qtype: RecordType | list[RecordType] = RecordType.A,
    ) -> list[Record]:
        """sends query and returns list of records, raises DNSBadResponse if response code != 0x00"""
        response = self.get_response_query(name, qtype=qtype)
        DNSBadResponse.raise_for_response(response)
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
            RecordType.NS,
            RecordType.MX,
            RecordType.TXT,
        ):
            rv += [(r.qtype.name, r.value) for r in self.query(s, t)]
        return rv


if __name__ == "__main__":
    import argparse
    import sys

    class NameSpace(argparse.Namespace):
        resolver: str
        type: str
        debug: bool
        name: str

    parser = argparse.ArgumentParser(description="Python DNS Client")
    parser.add_argument("--resolver", default="1.1.1.1")
    parser.add_argument(
        "-t",
        "--type",
        help="request record type (case insensetive)",
        default="A",
        nargs="+",
        type=str.upper,
        choices=["A", "AAAA", "CNAME", "MX", "NS", "TXT"],
    )
    parser.add_argument(
        "-d", "--debug", default=False, action=argparse.BooleanOptionalAction
    )
    parser.add_argument("name")

    args = parser.parse_args(namespace=NameSpace())

    try:
        qtypes = [RecordType[x] for x in args.type]
    except KeyError:
        # parser.error(
        #     "invalid record type; must be one of: "
        #     + ", ".join(set(RecordType._member_names_) - {"EMPTY"})
        # )
        parser.error("invalid dns record type")

    logging.basicConfig()
    logger.setLevel([logging.WARNING, logging.DEBUG][args.debug])

    with DNSClient(resolver_host=args.resolver) as client:
        try:
            for record in client.query(
                args.name,
                qtype=qtypes,
            ):
                print(record.value)
        except Exception as ex:
            logger.critical(ex)
            sys.exit(1)
