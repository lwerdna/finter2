import os
import io
import re
import types

from struct import unpack
from enum import Enum

#------------------------------------------------------------------------------
# data sources
#------------------------------------------------------------------------------

class SourceFile:
    def __init__(self, path):
        self.path = path
        self.length = os.path.getsize(path)
        self.fp = open(path, 'rb')

    def __del__(self):
        self.fp.close()

    def read(self, length):
        return self.fp.read(length)

    def read_at(self, offset, length, preserve_fp=True):
        mark = self.fp.tell()
        self.fp.seek(offset, io.SEEK_SET)
        result = self.fp.read(length)
        if preserve_fp:
            self.fp.seek(mark, io.SEEK_SET)
        return result

    def peek(self, length):
        pos = self.fp.tell()
        result = self.fp.read(length)
        self.fp.seek(pos, io.SEEK_SET)
        return result

    def tell(self):
        return self.fp.tell()

    def seek(self, offset, whence=io.SEEK_SET):
        print(f'self.fp: {self.fp}')
        print(f'offset: {offset}')
        print(f'whence: {whence}')
        return self.fp.seek(offset, whence)

    def is_eof(self):
        return self.fp.tell() >= self.length

    def __str__(self):
        return f'File(\"{self.path}\" len={self.length})'

# TODO: look into BytesIO or something
class SourceBuffer:
    def __init__(self, data):
        self.buffer = data
        self.length = len(data)
        self.offset = 0

    def read(self, length):
        result = self.buffer[self.offset: self.offset+length]
        self.offset = self.offset + length
        return result

    def read_at(self, offset, length, preserve_fp=True):
        mark = self.offset
        result = self.read(length)
        if preserve_fp:
            self.offset = mark
        return result

    def peek(self, length):
        return self.buffer[self.offset: self.offset+length]

    def tell(self):
        return self.offset

    def seek(self, offset, whence=io.SEEK_SET):
        if whence == io.SEEK_SET:
            self.offset = offset
        elif whence == io.SEEK_CUR:
            self.offset = self.offset + offset
        elif whence == io.SEEK_END:
            self.offset = len(self.buffer) + offset

        if offset < 0:
            raise OSError('Invalid argument')

        return self.offset

    def is_eof(self):
        return self.offset >= self.length

    def __str__(self):
        return f'Buff(len={len(self.buffer)})'

#------------------------------------------------------------------------------
# data accessors
#------------------------------------------------------------------------------

class Endian(Enum):
    LITTLE = 0
    BIG = 1

def int8(source, endian=Endian.LITTLE, peek=False):
    value = unpack('b', source.read(1))[0]
    if peek:
         source.seek(-1, io.SEEK_CUR)
    return value

def uint8(source, endian=Endian.LITTLE, peek=False):
    value = unpack('B', source.read(1))[0]
    if peek:
         source.seek(-1, io.SEEK_CUR)
    return value

def int16(source, endian=Endian.LITTLE, peek=False):
    fmt = '<h' if endian==Endian.LITTLE else '>h'
    value = unpack(fmt, source.read(2))[0]
    if peek:
         source.seek(-2, io.SEEK_CUR)
    return value

def uint16(source, endian=Endian.LITTLE, peek=False):
    fmt = '<H' if endian==Endian.LITTLE else '>H'
    value = unpack(fmt, source.read(2))[0]
    if peek:
         source.seek(-2, io.SEEK_CUR)
    return value

def uint24(source, endian=Endian.LITTLE, peek=False):
    data = source.read(3)
    if endian==endian.LITTLE:
        value = (data[0] << 16) | (data[1] << 8) | data[2]
    else:
        value = (data[2] << 16) | (data[1] << 8) | data[0]
    if peek:
         source.seek(-3, io.SEEK_CUR)
    return value

def int32(source, endian=Endian.LITTLE, peek=False):
    fmt = '<i' if endian==Endian.LITTLE else '>i'
    value = unpack(fmt, source.read(4))[0]
    if peek:
         source.seek(-4, io.SEEK_CUR)
    return value

def uint32(source, endian=Endian.LITTLE, peek=False):
    fmt = '<I' if endian==Endian.LITTLE else '>I'
    value = unpack(fmt, source.read(4))[0]
    if peek:
         source.seek(-4, io.SEEK_CUR)
    return value

def int64(source, endian=Endian.LITTLE, peek=False):
    fmt = '<q' if endian==Endian.LITTLE else '>q'
    value = unpack(fmt, source.read(8))[0]
    if peek:
         source.seek(-8, io.SEEK_CUR)
    return value

def uint64(source, endian=Endian.LITTLE, peek=False):
    fmt = '<Q' if endian==Endian.LITTLE else '>Q'
    value = unpack(fmt, source.read(8))[0]
    if peek:
         source.seek(-8, io.SEEK_CUR)
    return value

def double(source, endian=Endian.LITTLE, peek=False):
    fmt = '<d' if endian==Endian.LITTLE else '>d'
    value = unpack(fmt, source.read(8))[0]
    if peek:
         source.seek(-8, io.SEEK_CUR)
    return value

def dataUntil(source, terminator, peek=False):
    data = b''
    lenterm = len(terminator)
    while 1:
        sample = source.read(1)
        if sample == b'':
            raise EOFError(f'reached EOF before finding {terminator}')
        data += sample
        if len(data) >= lenterm:
            if data[-lenterm:] == terminator:
                break

    if peek:
        source.seek(-len(data), io.SEEK_CUR)

    return data

#------------------------------------------------------------------------------
# node
#------------------------------------------------------------------------------

class NodeType(Enum):
    T_UNKNOWN = 0
    T_U8 = 1
    T_8 = 2
    T_U16 = 3
    T_16 = 4
    T_U32 = 5
    T_32 = 6
    T_U64 = 7
    T_64 = 8
    T_d = 9
    T_EMPTY_CONTAINER = 10
    T_RAW = 11

class Node:
    def __init__(self, name, comment=None, source=None, offset=None, length=None, type_=NodeType.T_UNKNOWN):
        self.name = name
        self.comment = comment
        self.type = type_

        # where this data was found
        self.source = source
        self.offset = offset
        self.length = length

        self.parent = None
        self.children = []

        self.data = None
        self.data_raw = None

        self.setEndianLittle()

        self.cache = None

    def setEndianLittle(self):
        self.endian = Endian.LITTLE

    def setEndianBig(self):
        self.endian = Endian.BIG

    def getData(self):
        if self.cache is None:
            print(f'herp: {self}')
            pos = self.source.seek(self.offset, io.SEEK_SET)
            self.cache = self.source.read(self.length)

        return self.cache

    def addUint8(self, name, comment=None):
        offs = self.source.tell()
        value = uint8(self.source, self.endian)

        if comment is None:
            comment = '%d (0x%X)' % (value, value)
        elif type(comment) == types.FunctionType:
            comment = comment(value)

        child = Node(name, comment, source=self.source, offset=offs, length=1)
        self.children.append(child)
        return child

    def addUint32(self, name, comment=None):
        offs = self.source.tell()
        value = uint32(self.source, self.endian)

        if comment is None:
            comment = '%d (0x%X)' % (value, value)
        elif type(comment) == types.FunctionType:
            comment = comment(value)

        child = Node(name, comment, source=self.source, offset=offs, length=4)
        self.children.append(child)
        return child

    def addData(self, name, comment=None, length=None):
        assert length is not None

        pos = self.source.tell()
        data = self.source.read(length)

        if comment is None:
            comment = stringify_data(data)
        elif type(comment) == types.FunctionType:
            comment = comment(val)

        child = Node(name, comment, source=self.source, offset=pos, length=len(data))
        self.children.append(child)
        return child

    def addDataUntil(self, name, comment=None, terminator=None, peek=False):
        assert terminator is not None

        pos = self.source.tell()
        data = dataUntil(self.source, terminator, peek)

        if comment is None:
            comment = stringify_data(data)
        elif type(comment) == types.FunctionType:
            comment = comment(val)

        child = Node(name, comment, source=self.source, offset=pos, length=len(data))
        self.children.append(child)
        return child

    def addManual(self, name, comment=None, start=None, end=None, length=None):
        assert start is not None
        if length is None:
            length = end - start
        child = Node(name, comment, source=self.source, offset=start, length=length)
        self.children.append(child)
        return child

    def __str__(self):
        if self.offset is not None:
            assert self.length is not None
            return f'[{self.offset:X},{self.offset+self.length:X}) {self.name} {self.comment}'
        else:
            return f'Node(\"{self.name}\" src={self.source} chs={len(self.children)})'

#------------------------------------------------------------------------------
# misc
#------------------------------------------------------------------------------

def stringify_data(data):
    if type(data) == str:
        if len(string) > 15:
            return string[0:8] + '...' + string[-4:]
        return string
    elif type(data) == bytes:
        if len(data) > 15:
            sample = (data[0:8].decode('utf-8') + '...' + data[-4:].decode('utf-8')).replace('\x0a', '\\n')
        else:
            sample = data.decode('utf-8')

        sample = sample.replace('\n', '\\n')
        if sample.isprintable():
            return sample

        if len(data) > 15:
            return data[0:8].hex() + '...' + data[-4:].hex()
        else:
            return data.hex()

    raise Exception('cannot stringify data type {type(data)}')

#------------------------------------------------------------------------------
# hex printing stuff
#------------------------------------------------------------------------------

RED = '\x1B[31m'
GREEN = '\x1B[32m'
ORANGE = '\x1B[33m'
PURPLE = '\x1B[35m'
YELLOW = '\x1B[93m'
CYAN = '\x1B[96m'
NORMAL = '\x1B[0m'

def oha_comment(addr, comment):
    print(75*' '+CYAN+comment+NORMAL)

def oha(data, addr, comment=None, indent=0):
    """ offset, hex, ascii (OHA) of data """

    result = []
    va_last_printed = None
    va_lo = addr
    va_hi = addr + len(data)

    va = va_lo & 0xFFFFFFF0
    while va < va_hi:
        hex_str = ''
        ascii_str = ''

        if va == va_last_printed:
            addr_str = '        '
        else:
            addr_str = '%08X' % va
            va_last_printed = va

        for i in range(16):
            if va+i >= va_lo and va+i < va_hi:
                x = data[va+i - va_lo]
                hex_str += '%02X ' % x
                ascii_str += chr(x) if (x > 31 and x < 127) else '.'
            else:
                hex_str += '   '
                ascii_str += ' '

        if comment:
            #breakpoint()
            (cmargin, comment) = re.match(r'^(\s*)(.*)', comment).group(1, 2)
            comment = comment.split('\\n')
            print('%s%s%s%s %s %s%s%s %s%s%s%s' % \
                ('  '*indent, YELLOW, addr_str, NORMAL, hex_str, PURPLE, ascii_str, NORMAL, CYAN, cmargin, comment[0], NORMAL))
            for c in comment[1:]:
                print('%s%s%s' % (CYAN, 75*' '+cmargin + c, NORMAL))
            comment = ''
        else:
            print('%s%s%s%s %s %s%s%s' % \
                ('  '*indent, YELLOW, addr_str, NORMAL, hex_str, PURPLE, ascii_str, NORMAL))

        va += 16

    return '\n'.join(result)

#------------------------------------------------------------------------------
# test
#------------------------------------------------------------------------------

def print_recursive(node, indent=0):
    do_hex = False

    if do_hex:
        if not node.children:
            oha(node.getData(), node.offset, node.name, indent)
    else:
        print('  '*indent + str(node))

    for child in node.children:
        print_recursive(child, indent+1)

if __name__ == '__main__':
    fpath = '/tmp/foo.bin'

    with open(fpath, 'wb') as fp:
        fp.write(b'\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33' + b'\x41'*100)

    root = Node('root', source=SourceFile(fpath))

    root.addUint32("first")
    root.addUint32("second")
    root.addDataUntil('third', terminator=b'\x41\x41')

    print_recursive(root)

