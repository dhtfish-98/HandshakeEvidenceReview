"""Every integer and byte slice has a physical owner span."""

import struct
from .contracts import Gap


class Span:
    def __init__(self, data, start=0, size=None):
        self.data, self.start = data, start
        self.end = len(data) if size is None else start + size
        if start < 0 or self.end < start or self.end > len(data):
            raise Gap("span_out_of_bounds", max(0, start), "FAIL")

    def __len__(self):
        return self.end - self.start

    def check(self, offset, size, code="field_out_of_bounds"):
        if offset < 0 or size < 0 or offset + size > len(self):
            raise Gap(code, self.start + max(0, offset), "FAIL")

    def read(self, offset, size):
        self.check(offset, size)
        return self.data[self.start + offset : self.start + offset + size]

    def sub(self, offset, size):
        self.check(offset, size)
        return Span(self.data, self.start + offset, size)

    def num(self, offset, fmt, endian=">"):
        self.check(offset, struct.calcsize(fmt))
        return struct.unpack_from(endian + fmt, self.data, self.start + offset)[0]

    def u8(self, offset):
        return self.num(offset, "B")

    def u16(self, offset):
        return self.num(offset, "H")

    def u24(self, offset):
        return int.from_bytes(self.read(offset, 3), "big")


class Cursor:
    def __init__(self, span):
        self.span, self.pos = span, 0

    def take(self, size):
        result = self.span.sub(self.pos, size)
        self.pos += size
        return result

    def uint(self, size):
        return int.from_bytes(self.take(size).read(0, size), "big")

    def vector(self, width):
        return self.take(self.uint(width))

    def done(self):
        if self.pos != len(self.span):
            raise Gap("trailing_hello_bytes", self.span.start + self.pos, "FAIL")
