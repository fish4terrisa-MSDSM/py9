from enum import IntFlag


class Modes(IntFlag):
    DMMOUNT = 0x10000000
    DMEXCL = 0x20000000
    DMAPPEND = 0x40000000
    DMDIR = 0x80000000

    DMEXEC = 0x1
    DMWRITE = 0x2
    DMREAD = 0x4

    OREAD = 0
    OWRITE = 1
    ORDWR = 2
    OEXEC = 3
    OTRUNC = 16
    OCEXEC = 32
    ORCLOSE = 64
