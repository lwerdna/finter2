#!/usr/bin/env python

from Finter2 import *

def parse(source):
    root = Node('test', source=source)

    root.addUint32('foo')
    root.addUint32('bar')
    root.addUint32('baz')
    root.addUint32('cool')
    root.addUint32('foo2')
    root.addUint32('bar2')
    root.addUint32('baz2')
    root.addUint32('cool2')

    return root

if __name__ == '__main__':
    fpath = sys.argv[1]

    source = SourceFile(fpath)
    root = parse(source)


