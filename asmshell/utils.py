import os
import re
import sys


def ok(s: str):
    print(f"[+] {s}")


def ko(s: str):
    print(f"[-] {s}")


def exit():
    sys.exit()


def clear():
    if os.name == "posix":
        os.system("clear")
    elif os.name == "nt":
        os.system("cls")


def clean_str(s: str) -> str:
    s = re.sub(r"\s\s+", " ", s)
    s = s.strip().lower()
    return s


def hexdump(src, base=0x0, length=0x10, sep="."):
    FILTER = "".join(
        [(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(0xFF)]
    )
    lines = []
    for c in range(0, len(src), length):
        chars = src[c : c + length]
        hex_ = " ".join(["{:02x}".format(x) for x in chars])
        if len(hex_) > 0x18:
            hex_ = "{} {}".format(hex_[:0x18], hex_[0x18:])

        printable = "".join(
            ["{}".format((x <= 0x7F and FILTER[x]) or sep) for x in chars]
        )
        print(
            "{0:016x}: {1:{2}s} |{3:{4}s}|".format(
                c + base, hex_, length * 3, printable, length
            )
        )

    return lines
