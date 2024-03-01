# Python DNS Client

A simple dns client library for send queries.

* null-dependency
* threadsafe
* type hints

Install:

```bash
pip install dns-client
```

Examples:

```python
In [1]: from dns_client import DNSClient, DNSType

# use cloud to resolve queries
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
[Answer(name='www.linux.org', qtype=<DNSType.A: 1>, qclass=<DNSClass.IN: 1>, ttl=300, value='172.67.73.26'),
 Answer(name='www.linux.org', qtype=<DNSType.A: 1>, qclass=<DNSClass.IN: 1>, ttl=300, value='104.26.15.72'),
 Answer(name='www.linux.org', qtype=<DNSType.A: 1>, qclass=<DNSClass.IN: 1>, ttl=300, value='104.26.14.72')]

In [6]: client.query('www.linux.org', DNSType.AAAA)
Out[6]:
[Answer(name='www.linux.org', qtype=<DNSType.AAAA: 28>, qclass=<DNSClass.IN: 1>, ttl=300, value='2606:4700:20::681a:f48'),
 Answer(name='www.linux.org', qtype=<DNSType.AAAA: 28>, qclass=<DNSClass.IN: 1>, ttl=300, value='2606:4700:20::681a:e48'),
 Answer(name='www.linux.org', qtype=<DNSType.AAAA: 28>, qclass=<DNSClass.IN: 1>, ttl=300, value='2606:4700:20::ac43:491a')]

# but for MX each value is tuple where first element is priority
In [7]: client.query('yandex.ru', DNSType.MX)
Out[7]: [Answer(name='yandex.ru', qtype=<DNSType.MX: 15>, qclass=<DNSClass.IN: 1>, ttl=1078, value=(10, 'mx.yandex.ru'))]

In [8]: client.query('ya.ru', DNSType.TXT)
Out[8]:
[Answer(name='ya.ru', qtype=<DNSType.TXT: 16>, qclass=<DNSClass.IN: 1>, ttl=1200, value='_globalsign-domain-verification=dHoe580bPQ-lfi_vh-BEIwB4NAtUwURIzrzsivByVL'),
 Answer(name='ya.ru', qtype=<DNSType.TXT: 16>, qclass=<DNSClass.IN: 1>, ttl=1200, value='e1c8e4dd3d13fad0dd9e8ed54a1813ececd3d5412fb16c4ed2c0612332950fe'),
 Answer(name='ya.ru', qtype=<DNSType.TXT: 16>, qclass=<DNSClass.IN: 1>, ttl=1200, value='_globalsign-domain-verification=xUUDG4u7Zo56EmmFewz7Y4UK3MfAU7QSjAgBsy0w6q'),
 Answer(name='ya.ru', qtype=<DNSType.TXT: 16>, qclass=<DNSClass.IN: 1>, ttl=1200, value='v=spf1 redirect=_spf.yandex.ru'),
 Answer(name='ya.ru', qtype=<DNSType.TXT: 16>, qclass=<DNSClass.IN: 1>, ttl=1200, value='google-site-verification=SVTEeUiCU4KV-5qGw4o4JPok7mfsP8NtQTIdN6tt6Nw'),
 Answer(name='ya.ru', qtype=<DNSType.TXT: 16>, qclass=<DNSClass.IN: 1>, ttl=1200, value='_globalsign-domain-verification=eLi0_-xATuNmRfuTIX8VQIvgfyi7Od7Hph4V0yNisF')]

In [9]: adguard_client = DNSClient('94.140.14.14')

# unknown dns record types and some other returns raw bytes
In [10]: adguard_client.query('www.linux.org', DNSType.ANY)
Out[10]: [Answer(name='www.linux.org', qtype=<DNSType.UNKNOWN: -1>, qclass=<DNSClass.IN: 1>, ttl=3280, value=b'\x07RFC8482\x00')]

# exceptions
# axfr queries are useful for domain scanning
In [11]: adguard_client.query('www.linux.org', DNSType.AXFR)
---------------------------------------------------------------------------
BadResponse                               Traceback (most recent call last)
Cell In[11], line 1
...
BadResponse: dns server returns bad response code: 0x05

# you can get entire response instead list of answers
In [12]: adguard_client.get_response_query('www.linux.org', DNSType.AXFR)
Out[12]: Packet(header=Header(id=36118, is_response=True, opcode=<OpCode.QUERY: 0>, authoritative_answer=False, truncated=False, recursion_desired=True, recursion_available=False, reserved=2, response_code=<ResponseCode.REFUSED: 5>, num_questions=1, num_answers=0, num_authorities=0, num_additionals=0), questions=[Question(name='www.linux.org', qtype=<DNSType.AXFR: 252>, qclass=<DNSClass.IN: 1>)], answers=[])
```
