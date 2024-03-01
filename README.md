# Python DNS Client Library

A simple dns client library for send queries.

* null-dependency
* threadsafe
* type hints

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

# use cloudflare to resolve dns queries
In [2]: client = DNSClient('1.1.1.1')

# get host ip address
In [3]: client.gethostaddr('yandex.ru')
Out[3]: '5.255.255.77'

# get name servers
In [4]: client.get_name_servers('yandex.ru')
Out[4]: ['ns2.yandex.ru', 'ns1.yandex.ru']

# each value is string
In [5]: client.query('www.linux.org')
Out[5]:
[Record(name='www.linux.org', qtype=<RecordType.A: 1>, qclass=<RecordClass.IN: 1>, ttl=300, value='172.67.73.26'),
 Record(name='www.linux.org', qtype=<RecordType.A: 1>, qclass=<RecordClass.IN: 1>, ttl=300, value='104.26.15.72'),
 Record(name='www.linux.org', qtype=<RecordType.A: 1>, qclass=<RecordClass.IN: 1>, ttl=300, value='104.26.14.72')]

In [6]: client.query('www.linux.org', RecordType.AAAA)
Out[6]:
[Record(name='www.linux.org', qtype=<RecordType.AAAA: 28>, qclass=<RecordClass.IN: 1>, ttl=300, value='2606:4700:20::681a:f48'),
 Record(name='www.linux.org', qtype=<RecordType.AAAA: 28>, qclass=<RecordClass.IN: 1>, ttl=300, value='2606:4700:20::681a:e48'),
 Record(name='www.linux.org', qtype=<RecordType.AAAA: 28>, qclass=<RecordClass.IN: 1>, ttl=300, value='2606:4700:20::ac43:491a')]

# but for MX each value is tuple where first element is priority
In [7]: client.query('yandex.ru', RecordType.MX)
Out[7]: [Record(name='yandex.ru', qtype=<RecordType.MX: 15>, qclass=<RecordClass.IN: 1>, ttl=1078, value=(10, 'mx.yandex.ru'))]

In [8]: client.query('ya.ru', RecordType.TXT)
Out[8]:
[Record(name='ya.ru', qtype=<RecordType.TXT: 16>, qclass=<RecordClass.IN: 1>, ttl=1200, value='_globalsign-domain-verification=dHoe580bPQ-lfi_vh-BEIwB4NAtUwURIzrzsivByVL'),
 Record(name='ya.ru', qtype=<RecordType.TXT: 16>, qclass=<RecordClass.IN: 1>, ttl=1200, value='e1c8e4dd3d13fad0dd9e8ed54a1813ececd3d5412fb16c4ed2c0612332950fe'),
 Record(name='ya.ru', qtype=<RecordType.TXT: 16>, qclass=<RecordClass.IN: 1>, ttl=1200, value='_globalsign-domain-verification=xUUDG4u7Zo56EmmFewz7Y4UK3MfAU7QSjAgBsy0w6q'),
 Record(name='ya.ru', qtype=<RecordType.TXT: 16>, qclass=<RecordClass.IN: 1>, ttl=1200, value='v=spf1 redirect=_spf.yandex.ru'),
 Record(name='ya.ru', qtype=<RecordType.TXT: 16>, qclass=<RecordClass.IN: 1>, ttl=1200, value='google-site-verification=SVTEeUiCU4KV-5qGw4o4JPok7mfsP8NtQTIdN6tt6Nw'),
 Record(name='ya.ru', qtype=<RecordType.TXT: 16>, qclass=<RecordClass.IN: 1>, ttl=1200, value='_globalsign-domain-verification=eLi0_-xATuNmRfuTIX8VQIvgfyi7Od7Hph4V0yNisF')]

In [9]: client.get_all_records('ya.ru')
Out[9]:
[('A', '5.255.255.242'),
 ('A', '77.88.55.242'),
 ('AAAA', '2a02:6b8::2:242'),
 ('NS', 'ns2.yandex.ru'),
 ('NS', 'ns1.yandex.ru'),
 ('MX', (10, 'mx.yandex.ru')),
 ('TXT', 'v=spf1 redirect=_spf.yandex.ru'),
 ('TXT',
  '_globalsign-domain-verification=xUUDG4u7Zo56EmmFewz7Y4UK3MfAU7QSjAgBsy0w6q'),
 ('TXT',
  '_globalsign-domain-verification=eLi0_-xATuNmRfuTIX8VQIvgfyi7Od7Hph4V0yNisF'),
 ('TXT',
  '_globalsign-domain-verification=dHoe580bPQ-lfi_vh-BEIwB4NAtUwURIzrzsivByVL'),
 ('TXT',
  'google-site-verification=SVTEeUiCU4KV-5qGw4o4JPok7mfsP8NtQTIdN6tt6Nw'),
 ('TXT', 'e1c8e4dd3d13fad0dd9e8ed54a1813ececd3d5412fb16c4ed2c0612332950fe')]

In [10]: adguard_client = DNSClient('94.140.14.14')

# unknown dns record types and some other returns raw bytes
In [11]: adguard_client.query('www.linux.org', RecordType.ANY)
Out[11]: [Record(name='www.linux.org', qtype=<RecordType.UNKNOWN: -1>, qclass=<RecordClass.IN: 1>, ttl=3280, value=b'\x07RFC8482\x00')]

# exceptions
# axfr queries are useful for domain scanning
In [12]: adguard_client.query('www.linux.org', RecordType.AXFR)
---------------------------------------------------------------------------
DNSBadResponse                               Traceback (most recent call last)
Cell In[12], line 1
...
DNSBadResponse: dns server returns bad response code: 0x05

# you can get entire response instead list of records
In [13]: adguard_client.get_response_query('www.linux.org', RecordType.AXFR)
Out[13]: Packet(header=Header(id=36118, response=True, opcode=<OpCode.QUERY: 0>, authoritative_record=False, truncated=False, recursion_desired=True, recursion_available=False, reserved=2, rcode=<ResponseCode.REFUSED: 5>, num_questions=1, num_records=0, num_authorities=0, num_additionals=0), questions=[Question(name='www.linux.org', qtype=<RecordType.AXFR: 252>, qclass=<RecordClass.IN: 1>)], records=[])
```

CLI Usage:

```python
$ python -m dns_client ya.ru -t aaaa -d
DEBUG:__main__:set header flags: 0000000100100000
DEBUG:__main__:Packet(header=Header(id=40911, response=False, opcode=<OpCode.QUERY: 0>, authoritative=False, truncated=False, recursion_desired=True, recursion_available=False, reserved=False, authentic_data=True, check_disabled=False, rcode=<ResponseCode.NOERROR: 0>, num_questions=1, num_records=0, num_authorities=0, num_additionals=0), questions=[Question(name='ya.ru', qtype=<RecordType.AAAA: 28>, qclass=<RecordClass.IN: 1>)], records=[])
DEBUG:__main__:get header flags: 0000000100100000
DEBUG:__main__:raw query data: 9f cf 01 20 00 01 00 00 00 00 00 00 02 79 61 02 72 75 00 00 1c 00 01
DEBUG:__main__:set header flags: 1000000110000000
DEBUG:__main__:Packet(header=Header(id=40911, response=True, opcode=<OpCode.QUERY: 0>, authoritative=False, truncated=False, recursion_desired=True, recursion_available=True, reserved=False, authentic_data=False, check_disabled=False, rcode=<ResponseCode.NOERROR: 0>, num_questions=1, num_records=1, num_authorities=0, num_additionals=0), questions=[Question(name='ya.ru', qtype=<RecordType.AAAA: 28>, qclass=<RecordClass.IN: 1>)], records=[Record(name='ya.ru', qtype=<RecordType.AAAA: 28>, qclass=<RecordClass.IN: 1>, ttl=528, value='2a02:6b8::2:242')])
DEBUG:__main__:get header flags: 1000000110000000
DEBUG:__main__:function query tooks 0.029s
2a02:6b8::2:242
```
