"""Python client library for sending DNS queries."""

__author__ = "Sergey M"
__version__ = "0.2.0"

from .client import DNSClient
from .errors import ConnectionError, DNSError, SocketError
from .protocol import Header, Packet, Question, Record, RecordClass, RecordType

__all__: tuple[str, ...] = (
    "DNSError",
    "DNSClient",
    "ConnectionError",
    "Header",
    "Packet",
    "Question",
    "Record",
    "RecordClass",
    "RecordType",
    "SocketError",
)
