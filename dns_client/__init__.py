"""Python client library for sending DNS queries."""

__author__ = "Sergey M"
__version__ = "0.2.4"

from .client import DNSClient
from .errors import ClientError, ConnectionError, DNSError
from .protocol import Header, Packet, Question, Record, RecordClass, RecordType

__all__: tuple[str, ...] = (
    "ClientError",
    "ConnectionError",
    "DNSClient",
    "DNSError",
    "Header",
    "Packet",
    "Question",
    "Record",
    "RecordClass",
    "RecordType",
)
