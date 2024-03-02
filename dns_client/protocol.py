# https://www.geeksforgeeks.org/dns-message-format/
# https://copyprogramming.com/howto/how-to-query-dns-records-using-python
# https://implement-dns.wizardzines.com/book/part_1
# https://implement-dns.wizardzines.com/book/part_2
# https://support.riverbed.com/apis/steelscript/packets/tutorial.html
# https://github.com/Habbie/hello-dns/blob/master/tdns/
# https://github.com/lun-4/zigdig/blob/master/src/packet.zig
# https://github.com/indented-automation/Indented.Net.Dns/blob/main/Indented.Net.Dns/
# https://github.com/cmol/dnsmessage/blob/main/lib/dnsmessage/resource_record.rb
from __future__ import annotations

import dataclasses
import operator
import secrets
import socket
import struct
import typing
from enum import IntEnum

from .log import logger
from .utils import BitsReader, BitsWriter, isiterable


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


class RecordClass(IntEnum):
    EMPTY = 0
    IN = 1  # INternet
    CH = 3  # CHaos
    HS = 4
    NONE = 254
    ANY = 256


T = typing.TypeVar("T")


class PacketHandler:
    def parse(self, fp: typing.BinaryIO) -> None:
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        raise NotImplementedError

    @classmethod
    def read_from(cls: typing.Type[T], fp: typing.BinaryIO) -> T:
        o = cls()
        o.parse(fp)
        return o


# ! — big-endian, используемый как стандарт при передаче по сети (все компьютеры little-endian, если че)
HEADER_FORMAT = struct.Struct("!6H")


class OpCode(IntEnum):
    QUERY = 0
    INVERSE = 1  # Inverse Query (OBSOLETE). See rfc3425.
    STATUS = 2
    # reserved


class ResponseCode(IntEnum):
    NOERROR = 0
    FORMERR = 1
    SERVFAIL = 2
    NXDOMAIN = 3
    NOTIMP = 4
    REFUSED = 5
    NOTAUTH = 9
    BADVERS = 16


@dataclasses.dataclass
class Header(PacketHandler):
    """Packet Header"""

    # id: int = dataclasses.field(
    #     default_factory=lambda: secrets.randbits(16)
    # )
    id: int = 0  # 2 bytes

    # устанавливаются через flags (2 bytes)
    response: bool = False  # 0. QR: query=0
    opcode: OpCode = OpCode.QUERY  # 4 bits (!bytes)
    authoritative: bool = False  # AA
    truncated: bool = False  # TC
    recursion_desired: bool = False  # RD
    recursion_available: bool = False  # RA
    reserved: bool = False  # Z (1 bit) alawys false (0)
    authentic_data: bool = False  # AD (1 bit)
    check_disabled: bool = False  # CD (1 bit)
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
        writer.write(self.authoritative)
        writer.write(self.truncated)
        writer.write(self.recursion_desired)
        writer.write(self.recursion_available)
        writer.write(self.reserved)
        writer.write(self.authentic_data)
        writer.write(self.check_disabled)
        writer.write(self.rcode, 4)
        logger.debug(f"get header flags: {writer.result:016b}")
        return writer.result

    @flags.setter
    def flags(self, v: int) -> None:
        logger.debug(f"set header flags: {v:016b}")
        reader = BitsReader(v, 16)
        self.response = reader.read_bool()
        self.opcode = OpCode(reader.read(4))
        self.authoritative = reader.read_bool()
        self.truncated = reader.read_bool()
        self.recursion_desired = reader.read_bool()
        self.recursion_available = reader.read_bool()
        self.reserved = reader.read_bool()
        self.authentic_data = reader.read_bool()
        self.check_disabled = reader.read_bool()
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

    def parse(self, fp: typing.BinaryIO) -> None:
        (
            self.id,
            self.flags,
            self.num_questions,
            self.num_records,
            self.num_authorities,
            self.num_additionals,
        ) = HEADER_FORMAT.unpack(fp.read(12))


def encode_name(s: str) -> bytes:
    """Кодирует имя. Имя хоста разбивается на сегменты по точке, каждому
    сегменту прешествует его длина = 1 байт, в конце всегда 0x00"""
    rv = b""
    for p in s.rstrip(".").encode().split(b"."):
        rv += len(p).to_bytes() + p
    return rv + b"\0"


def read_name(fp: typing.BinaryIO) -> str:
    rv = []
    while (length := int.from_bytes(fp.read(1))) > 0:
        # сжатые данные
        if length & 0xC0:
            # length = ((length & 0x3F) << 8) | *p;
            length = ((length & 0x3F) << 8) | int.from_bytes(fp.read(1))
            cur_pos = fp.tell()
            fp.seek(length)
            rv.append(read_name(fp))
            fp.seek(cur_pos)
            break
        rv.append(fp.read(length).decode())
    return ".".join(rv)


@dataclasses.dataclass
class Question(PacketHandler):
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

    def parse(self, fp: typing.BinaryIO) -> None:
        self.name = read_name(fp)
        self.qtype = RecordType(
            int.from_bytes(
                fp.read(2),
            ),
        )
        self.qclass = RecordClass(
            int.from_bytes(
                fp.read(2),
            ),
        )


@dataclasses.dataclass
class Record(PacketHandler):
    """Response Record"""

    name: str | None = None
    qtype: int = RecordType.EMPTY
    qclass: int = RecordClass.EMPTY
    ttl: int = 0
    value: typing.Any = None

    def _parse_value(self, fp: typing.BinaryIO) -> typing.Any:
        data_len = int.from_bytes(fp.read(2))
        match self.qtype:
            case RecordType.A:
                return socket.inet_ntoa(fp.read(data_len))
            case RecordType.AAAA:
                return socket.inet_ntop(socket.AF_INET6, fp.read(data_len))
            case RecordType.MX:
                pri = int.from_bytes(fp.read(2))  # priority
                return pri, read_name(fp)
            case RecordType.CNAME | RecordType.NS | RecordType.PTR:
                return read_name(fp)
            case RecordType.TXT:
                # https://en.m.wikipedia.org/wiki/TXT_record
                # первый байт - это длина текстовой записи
                return fp.read(data_len)[1:].decode()
            case RecordType.EMPTY:
                raise ValueError()
            case _:
                return fp.read(data_len)

    def parse(self, fp: typing.BinaryIO) -> None:
        self.name = read_name(fp)
        self.qtype = RecordType(
            int.from_bytes(
                fp.read(2),
            ),
        )
        self.qclass = RecordClass(
            int.from_bytes(
                fp.read(2),
            ),
        )
        self.ttl = int.from_bytes(fp.read(4))
        self.value = self._parse_value(fp)


@dataclasses.dataclass
class Packet(PacketHandler):
    """Query or Response Packet"""

    header: Header | None = None
    questions: list[Question] = dataclasses.field(default_factory=list)
    records: list[Record] = dataclasses.field(default_factory=list)
    # TODO: additionals and etc

    def parse(self, fp: typing.BinaryIO) -> None:
        self.header = Header.read_from(fp)
        self.questions = [
            Question.read_from(fp) for _ in range(self.header.num_questions)
        ]
        self.records = [
            Record.read_from(fp) for _ in range(self.header.num_records)
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
    def response_ok(self) -> bool:
        return self.is_response and self.response_code == ResponseCode.NOERROR

    @property
    def question(self) -> Question | None:
        try:
            return self.questions[0]
        except IndexError:
            pass

    @classmethod
    def build_query(
        cls: typing.Type[Packet],
        qname: str,
        qtype: RecordType | list[RecordType] = RecordType.A,
        /,
    ) -> Packet:
        questions = [
            Question(qname, typ, qclass=RecordClass.IN)
            for typ in (qtype if isiterable(qtype) else [qtype])
        ]

        if len(questions) > 1:
            logger.warning("most name servers don't support multiple questions")

        # эти флаги устанавливает dig
        # Flags: 0x0120 Standard query
        # 0... .... .... .... = Response: Message is a query
        # .000 0... .... .... = Opcode: Standard query (0)
        # .... ..0. .... .... = Truncated: Message is not truncated
        # .... ...1 .... .... = Recursion desired: Do query recursively
        # .... .... .0.. .... = Z: reserved (0)
        # .... .... ..1. .... = AD bit: Set
        # .... .... ...0 .... = Non-authenticated data: Unacceptable
        return cls(
            header=Header(
                id=secrets.randbits(16),
                num_questions=len(questions),
                flags=0x120,
            ),
            questions=questions,
        )
