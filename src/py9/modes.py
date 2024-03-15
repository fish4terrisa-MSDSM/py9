from enum import IntEnum


class Modes(IntEnum):
    DMDIR = 0x80000000
    DMAPPEND = 0x40000000
    DMEXCL = 0x20000000
    DMMOUNT = 0x10000000
    DMREAD = 0x4
    DMWRITE = 0x2
    DMEXEC = 0x1
    OEXEC = 0x3
    ORDWR = 0x2
    OWRITE = 0x1
    OREAD = 0x0
