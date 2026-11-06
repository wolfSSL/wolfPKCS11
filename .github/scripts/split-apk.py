#!/usr/bin/env python3
"""Split a signed Alpine package for signature checking.

usage: split-apk.py <package.apk> <key name> <output prefix>

Writes <prefix>.sig, <prefix>.control.gz and <prefix>.data.tar.gz once the
data matches the control stream's datahash.
"""

import hashlib
import io
import sys
import tarfile
import zlib


def gzip_streams(data):
    streams = []
    while data:
        inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)
        plain = inflate.decompress(data)
        used = len(data) - len(inflate.unused_data)
        streams.append((data[:used], plain))
        data = inflate.unused_data
    return streams


def member(plain, name):
    with tarfile.open(fileobj=io.BytesIO(plain)) as tar:
        try:
            return tar.extractfile(name).read()
        except KeyError:
            sys.exit("missing " + name)


def main():
    apk, key, prefix = sys.argv[1:4]
    with open(apk, "rb") as f:
        streams = gzip_streams(f.read())
    if len(streams) < 3:
        sys.exit(apk + ": not a signed package")

    sig = member(streams[0][1], ".SIGN.RSA." + key)
    info = member(streams[1][1], ".PKGINFO").decode()
    datahash = [line.split(" = ", 1)[1] for line in info.splitlines()
                if line.startswith("datahash = ")]
    payload = b"".join(raw for raw, _ in streams[2:])
    if datahash != [hashlib.sha256(payload).hexdigest()]:
        sys.exit(apk + ": data does not match datahash")

    with open(prefix + ".sig", "wb") as f:
        f.write(sig)
    with open(prefix + ".control.gz", "wb") as f:
        f.write(streams[1][0])
    with open(prefix + ".data.tar.gz", "wb") as f:
        f.write(payload)


if __name__ == "__main__":
    main()
