#!/usr/bin/env python

import argparse
import logging
import sys

from protocols.kmip import KMIP
from protocols.pkcs11 import PKCS11
import netem


def parse_args():
    parser = argparse.ArgumentParser("PKCS#11/KMIP test runner")
    parser.add_argument("protocol", choices=["kmip", "pkcs11"])
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Show debug output", default=False
    )

    def positive_int(val: str) -> int:
        res = int(val)
        if res <= 0:
            raise ValueError("Argument must be a positive integer")
        return res

    parser.add_argument(
        "--delay", type=positive_int, help="Network delay to add (in milliseconds)"
    )

    args, _ = parser.parse_known_args(sys.argv[1:])
    return args


def main():
    args = parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.delay:
        netem.add_delay(args.delay)

    protocol = KMIP() if args.protocol == "kmip" else PKCS11()
    protocol.set_up()
    protocol.run_tests()

    logging.debug("All done!")


if __name__ == "__main__":
    main()
