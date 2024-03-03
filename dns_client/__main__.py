import argparse
import logging
import sys
from functools import partial

from .client import DNSClient
from .log import disable_logger, logger
from .protocol import Packet, RecordType
from .utils import split_chunks

print_err = partial(print, file=sys.stderr)


def print_response(response: Packet) -> None:
    header = response.header

    print_err("Response Flags =", hex(header.flags))
    print_err()

    bits_str = f"{header.flags:016b}"

    attrs_len = {
        "response": 1,
        "opcode": 4,
        "authoritative": 1,
        "truncated": 1,
        "recursion_desired": 1,
        "recursion_available": 1,
        "reserved": 1,
        "authentic_data": 1,
        "check_disabled": 1,
        "rcode": 4,
    }

    offset = 0
    for attr, length in attrs_len.items():
        data = (
            bits_str[offset : offset + length]
            .rjust(offset + length, ".")
            .ljust(len(bits_str), ".")
        )
        data = " ".join(split_chunks(data, 4))
        label = attr.title().replace("_", " ")
        value = getattr(header, attr)
        print_err(data, "=", label, f"({value!r})")
        offset += length

    print_err()

    print_err("Number of Records\t:", header.num_records)
    print_err("Number of Questions\t:", header.num_questions)
    print_err("Number of Authorities\t:", header.num_authorities)
    print_err("Number of Additionals\t:", header.num_additionals)

    print_err()


class NameSpace(argparse.Namespace):
    debug: bool
    host: str
    name: str
    over_tls: bool
    port: int
    print_response: bool
    type: str


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Python DNS Client")
    parser.add_argument("-H", "--host", default="1.1.1.1", help="dns host")
    parser.add_argument("-p", "--port", type=int, help="dns port")
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
        "-d",
        "--debug",
        default=False,
        help="show debug info",
        action="store_true",
    )
    parser.add_argument(
        "-pr",
        "--print-response",
        "--print",
        default=False,
        help="print response info",
        action="store_true",
    )
    parser.add_argument(
        "--over-tls",
        "--tls",
        default=False,
        help="use tcp/tls instead udp",
        action="store_true",
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

    with DNSClient(args.host, args.port, over_tls=args.over_tls) as client:
        try:
            response = client.get_query_response(
                args.name,
                qtype=qtypes,
            )

            if args.print_response:
                with disable_logger():
                    print_response(response)

            for record in response.records:
                print(record.value)
        except Exception as ex:
            logger.exception(ex)
            sys.exit(1)
