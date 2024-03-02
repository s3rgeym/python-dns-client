import argparse
import logging
import sys

from .client import DNSClient
from .log import logger
from .protocol import RecordType


class NameSpace(argparse.Namespace):
    host: str
    port: int
    type: str
    debug: bool
    name: str


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Python DNS Client")
    parser.add_argument("-H", "--host", default="1.1.1.1", help="dns host")
    parser.add_argument("-p", "--port", default=53, type=int, help="dns port")
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
        action=argparse.BooleanOptionalAction,
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

    with DNSClient(args.host, args.port) as client:
        try:
            for record in client.query(
                args.name,
                qtype=qtypes,
            ):
                print(record.value)
        except Exception as ex:
            logger.critical(ex)
            sys.exit(1)
