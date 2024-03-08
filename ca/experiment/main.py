#!/usr/bin/env python

import argparse
import logging
import sys

from p11 import PKCS11


def parse_args():
    parser = argparse.ArgumentParser("PKCS#11/KMIP test runner")
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Show debug output", default=False
    )
    args, _ = parser.parse_known_args(sys.argv)
    return args


def main():
    args = parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    protocol = PKCS11()
    protocol.set_up()
    protocol.run_tests()

    logging.debug("All done!")


if __name__ == "__main__":
    main()
