#!/usr/bin/env python

import os
import sys

from Finter2 import *

def parse(source):
    root = Node('rsa private key', source=source)

    line = dataUntil(source, b'\x0a', peek=True)
    assert line == b'-----BEGIN RSA PRIVATE KEY-----\x0a'
    root.addData('marker', length=len(line))

    # consume base64 string
    b64str = b''
    b64start, b64end = None, None
    b64node = None
    while True:
        line = dataUntil(source, b'\x0a', peek=True)

        if line.startswith(b'Proc-Type:'):
            root.addData('header', length=len(line))
            continue
        elif line.startswith(b'DEK-Info:'):
            root.addData('header', length=len(line))
            continue
        elif line.isspace():
            root.addData('space', length=len(line))
            continue
        elif line == b'-----END RSA PRIVATE KEY-----\x0a':
            # add the base64 text
            length = source.tell() - b64start
            source.seek(b64start)
            b64node = root.addData('data', 'key, base64', length=length)
            # add the end marker
            root.addData('marker', length=len(line))
            b64end = source.tell()
            break
        else:
            if b64start is None:
                b64start = source.tell()
            b64str += line.strip()
            # skip this line
            source.seek(len(line), io.SEEK_CUR)

    # add subnode with decoded base64 string
    import base64
    subsource = SourceBuffer(base64.b64decode(b64str))

    import test
    subnode = test.parse(subsource)
    b64node.children.append(subnode)

    return root

if __name__ == '__main__':
    fpath = sys.argv[1]

    source = SourceFile(fpath)
    root = parse(source)

    print_recursive(root)
