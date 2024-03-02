# Python DNS Client Library

[ ![PyPI - Python Version](https://img.shields.io/pypi/v/dns-client) ]()
[ ![PyPI - Python Version](https://img.shields.io/pypi/pyversions/dns-client) ]()
[ ![PyPI - Downloads](https://img.shields.io/pypi/dm/dns-client) ]()

Python client library for sending DNS queries.

* null-dependency
* threadsafe
* type hints
* contains adapter for requests

Install:

```bash
# from pypi.org
pip install dns-client

# latest commit
pip install git+https://github.com/s3rgeym/python-dns-client.git
```

Examples:

```python
In [1]: from dns_client import DNSClient, RecordType

In [2]: c = DNSClient('1.1.1.1')

In [3]: c.query('ya.ru', RecordType.AAAA)
Out[3]: [Record(name='ya.ru', qtype=<RecordType.AAAA: 28>, qclass=<RecordClass.IN: 1>, ttl=76, value='2a02:6b8::2:242')]

In [4]: c.query('ya.ru', RecordType.MX)
Out[4]: [Record(name='ya.ru', qtype=<RecordType.MX: 15>, qclass=<RecordClass.IN: 1>, ttl=2242, value=(10, 'mx.yandex.ru'))]

In [5]: c.get_query_response('ya.ru')
Out[5]: Packet(header=Header(id=47527, response=True, opcode=<OpCode.QUERY: 0>, authoritative=False, truncated=False, recursion_desired=True, recursion_available=True, reserved=False, authentic_data=False, check_disabled=False, rcode=<ResponseCode.NOERROR: 0>, num_questions=1, num_records=2, num_authorities=0, num_additionals=0), questions=[Question(name='ya.ru', qtype=<RecordType.A: 1>, qclass=<RecordClass.IN: 1>)], records=[Record(name='ya.ru', qtype=<RecordType.A: 1>, qclass=<RecordClass.IN: 1>, ttl=266, value='77.88.55.242'), Record(name='ya.ru', qtype=<RecordType.A: 1>, qclass=<RecordClass.IN: 1>, ttl=266, value='5.255.255.242')])

In [6]: c.get_all_records('ya.ru')
Out[6]:
[('A', '5.255.255.242'),
 ('A', '77.88.55.242'),
 ('AAAA', '2a02:6b8::2:242'),
 ('MX', (10, 'mx.yandex.ru')),
 ('NS', 'ns1.yandex.ru'),
 ('NS', 'ns2.yandex.ru'),
 ('TXT',
  '_globalsign-domain-verification=eLi0_-xATuNmRfuTIX8VQIvgfyi7Od7Hph4V0yNisF'),
 ('TXT',
  '_globalsign-domain-verification=xUUDG4u7Zo56EmmFewz7Y4UK3MfAU7QSjAgBsy0w6q'),
 ('TXT',
  'google-site-verification=SVTEeUiCU4KV-5qGw4o4JPok7mfsP8NtQTIdN6tt6Nw'),
 ('TXT', 'v=spf1 redirect=_spf.yandex.ru'),
 ('TXT',
  '_globalsign-domain-verification=dHoe580bPQ-lfi_vh-BEIwB4NAtUwURIzrzsivByVL'),
 ('TXT', 'e1c8e4dd3d13fad0dd9e8ed54a1813ececd3d5412fb16c4ed2c0612332950fe')]
```

You can use `dns-client` with `requests`:

```python
from dns_client.adapters.requests import DNSClientSession

s = DNSClientSession('1.1.1.1')
s.get('https://google.com')
```

CLI Usage:

```bash
$ python -m dns_client ya.ru -t ns -H 127.0.0.1 --print
Response Flags = 0x8180

1... .... .... .... = Response (True)
.000 0... .... .... = Opcode (<OpCode.QUERY: 0>)
.... .0.. .... .... = Authoritative (False)
.... ..0. .... .... = Truncated (False)
.... ...1 .... .... = Recursion Desired (True)
.... .... 1... .... = Recursion Available (True)
.... .... .0.. .... = Reserved (False)
.... .... ..0. .... = Authentic Data (False)
.... .... ...0 .... = Check Disabled (False)
.... .... .... 0000 = Rcode (<ResponseCode.NOERROR: 0>)

Number of Records     : 2
Number of Questions   : 1
Number of Authorities : 0
Number of Additionals : 1

ns2.yandex.ru
ns1.yandex.ru
```

| Arg | Desc |
| --- | --- |
| `-t` | record type |
| `-H` | dns address |
| `--print` | print response |

See all arguments:

```bash
python -m dns_client -h
```
