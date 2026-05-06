#!/usr/bin/env python

# References:
# 1. A Warm Welcome to ASN.1 and DER
#    https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/

import io
import sys

from Finter2 import *

def read_length(source):
    # normal length
    length = uint8(source)

    # extended length?
    if length >> 7:
        lbytes = length & 0x7F

        # indefinite length?
        if lbytes == 0:
            raise Exception('indefinite lengths not supported')

        length = int.from_bytes(source.read(lbytes), 'big')

    return length

# returns Node, length
def parse_length(source):
    pos = source.tell()
    length = read_length(source)
    return Node('length', f'length=0x{length:x}', source=source, offset=pos, length=(source.tell() - pos)), length

def parse_integer(source):
    start = source.tell()

    # skip tag
    source.read(1)
    # get length
    length = read_length(source)
    # get bytes
    data = source.read(length)
    # check msb for neg flag
    factor = 1
    if data[0] & 0x80:
        factor = -1
        data[0] = data[0] & 0x7F

    value = int.from_bytes(data, 'big') * factor

    tagFromPosition(source, start, str(value))

# type is called a "tag" in ASN.1 language
def parse_tlv(source):
    result = Node('TLV', source=source)

    start = source.tell()

    tag_ = uint8(source, peek=True)
    #  bits: AABCCCCC
    #
    #    AA: class
    #     B: constructed/primitive
    # CCCCC: type
    type_ = tag_ & 0x1F #
    nonprim = (tag_ >> 5) & 1
    class_ = tag_ >> 6

    # TODO: use enums
    #if class_ == 0 and type_ == 2:
    #    parse_integer(source)
    #    return

    # TODO: use enums
    if class_ == 0:
        type_name = {   2: 'INTEGER',
                        3: 'BIG_STRING',
                        4: 'OCTET_STRING',
                        5: 'NULL',
                        6: 'OBJECT_ID',
                        12: 'UTF8String',
                        16: 'SEQUENCE[OF]',
                        17: 'SET[OF]',
                        19: 'PrintableString',
                        22: 'IA5String',
                        23: 'UTCTime',
                        24: 'GeneralizedTime'
                    }.get(type_, '(UNKNOWN)')
    else:
        type_name = '?'

    class_ = ['Universal', 'Application', 'Context-specific', 'Private'][type_ >> 6]

    result.addUint8('tag', f'({class_}.{type_name})')

    mark = source.tell()

    indefinite = False
    length_node, length = parse_length(source)
    result.children.append(length_node)

    #tagFromPosition(source, mark, f'length: {length:X}h')

    if nonprim:
        limit = source.tell() + length

        while source.tell() < limit:
            # nested tlv
            subres = parse_tlv(source)
            result.children.append(subres)
    else:
        # primitive
        result.addManual('data', start=source.tell(), length=length)

    return result

###############################################################################
# "main"
###############################################################################

def parse(source):
    # start with type SEQUENCE, EXTENDED 2-byte length
    if source.peek(2) != b'\x30\x82':
        return

    root = Node('DER', source=source)
    root.setEndianLittle()

    breakpoint()
    while not source.is_eof():
        subres = parse_tlv(source)
        root.children.append(subres)

    return root

if __name__ == '__main__':
    fpath = sys.argv[1]
    source = SourceFile(fpath)
    root = parse(source)

    print_recursive(root)
