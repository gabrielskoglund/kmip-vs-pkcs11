#!/usr/bin/env python

import argparse
import logging
import pathlib
import sys

from protocols.common import OUTPUT_FILE
from protocols.kmip import KMIP
from protocols.pkcs11 import PKCS11


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("protocol", choices=["kmip", "pkcs11"])
    parser.add_argument("--rtt-ms", type=int, required=True)
    parser.add_argument("-d", "--debug", action="store_true", default=False)
    parser.add_argument("--kmip-batch-size", type=int, default=None)

    args, _ = parser.parse_known_args(sys.argv[1:])
    return args


def main():
    output_file = pathlib.Path(OUTPUT_FILE)
    if not (output_file.exists() and output_file.is_file()):
        raise RuntimeError(
            f"{OUTPUT_FILE} is not available, make sure it is mounted in the container"
        )

    args = parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.protocol == "kmip":
        protocol = KMIP(rtt_ms=args.rtt_ms, batch_size=args.kmip_batch_size)
    else:
        protocol = PKCS11(rtt_ms=args.rtt_ms)
    protocol.set_up()
    protocol.run_experiment()

    logging.debug("All done!")


if __name__ == "__main__":
    main()
