#!/usr/bin/env python

import logging
from p11 import PKCS11


def main():
    logging.basicConfig(level=logging.DEBUG)

    protocol = PKCS11()
    protocol.set_up()
    protocol.run_tests()

    logging.debug("All done!")


if __name__ == "__main__":
    main()
