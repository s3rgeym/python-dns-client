import functools
import time
import typing
from dataclasses import dataclass, field


# байтоебство мне не по нраву, а поэтому обернем все в классы
@dataclass
class BitsReader:
    """
    Read bits from value

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
    offset: int = field(init=0, repr=0, default=0)

    def read(self, n: int = 1) -> int:
        """Read n bits from value"""
        assert n >= 1
        mask = (1 << n) - 1
        shift = self.length - n - self.offset
        try:
            # ValueError: negative shift n
            return (self.value >> shift) & mask
        finally:
            self.offset += n

    def read_bool(self) -> bool:
        """Read 1 bit as bool"""
        return self.read() > 0

    read_flag = read_bool

    def seek(self, offset: int = 0) -> None:
        self.offset = offset


# В этом случае без классов и невозможно, т.к. в питоне нельзя передавать
# простые типы по ссылке как в PHP
@dataclass
class BitsWriter:
    """Set bits"""

    length: int
    offset: int = field(init=0, repr=0, default=0)
    result: int = field(init=0, repr=0, default=0)

    def write(self, data: int | bool, n: int = 1) -> None:
        """set n bits from data at current offset"""
        assert n >= 1
        mask = (1 << n) - 1
        shift = self.length - n - self.offset
        # можно еще предварительно обнулять флаги
        self.result |= (data & mask) << shift
        self.offset += n


def split_chunks(seq: typing.Sequence, n: int) -> list[str]:
    return [seq[i : i + n] for i in range(0, len(seq), n)]


def split_hex(b: bytes) -> list[str]:
    return split_chunks(b.hex(), 2)


def isiterable(v: typing.Any) -> bool:
    return isinstance(v, typing.Sequence) and not isinstance(v, (str, bytes))


# modified from https://stackoverflow.com/a/73026174/2240578
def ttl_lru_cache(ttl: float, **cache_kwargs: typing.Any):
    def wrapper(f):
        @functools.lru_cache(**cache_kwargs)
        def inner(__ttl, *args, **kwargs):
            return f(*args, **kwargs)

        return lambda *args, **kwargs: inner(
            time.monotonic() // ttl, *args, **kwargs
        )

    return wrapper
