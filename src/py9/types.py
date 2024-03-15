from enum import IntEnum


class Types(IntEnum):
    QTDIR = 0x80
    QTAPPEND = 0x40
    QTEXCL = 0x20
    QTMOUNT = 0x10
    QTAUTH = 0x08
    QTFILE = 0x00
