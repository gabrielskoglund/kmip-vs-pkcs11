import argparse
import csv
import json
import multiprocessing
import random
import sys
import time
import timeit

import jsonschema

import grpc_api
import kmip_api
import rest_api
import mock_hsm

# JSON schema used for the experiment configuration
experiments_schema = {
    "title": "experiment_config",
    "description": "A configuration for a set of experiments to run",
    "type": "object",
    "properties": {
        "repeat": {
            "type": "integer",
            "minimum": 1,
            "default": 1,
            "description": "How many times to repeat each experiment",
        },
        "shuffle": {
            "type": "boolean",
            "default": "false",
            "description": "Whether to shuffle the experiment list before running",
        },
        "experiments": {
            "description": "A list of individual experiments",
            "type": "array",
            "items": {
                "Properties to test in this experiment" "type": "object",
                "properties": {
                    "api": {
                        "enum": ["kmip", "grpc", "rest"],
                        "description": "Which type of HSM api to use",
                    },
                    "hsm_capacity": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "HSM capacity in terms of signatures/second",
                    },
                    "num_signatures": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "How many signatures to perform",
                    },
                    "kmip_batch_count": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Number of KMIP sign operations per request",
                    },
                    "threaded": {
                        "type": "boolean",
                        "default": "false",
                        "description": "Whether to run the server in threaded mode",
                    },
                },
                "required": ["api", "hsm_capacity", "num_signatures"],
                # Require kmip_batch_count to be set if the KMIP API is used
                "if": {"properties": {"api": {"const": "kmip"}}},
                "then": {"required": ["kmip_batch_count"]},
            },
        },
    },
    "required": ["experiments"],
}


class Experiment:
    """
    Experiment represents an experiment to run.

    :param api: the HSM API to use ("kmip", "gprc" or "rest").
    :param hsm_capacity: the HSM capacity in terms of signatures/second.
    :param num_signatures: how many signatures to perform.
    :param kmip_batch_count: how many kmip operations to batch per request.
    :param threaded: whether to run the client and server in threaded mode.
    """

    def __init__(
        self,
        api: str,
        hsm_capacity: int,
        num_signatures: int,
        kmip_batch_count=None,
        threaded: bool = False,
    ):
        self.api = api
        self.hsm_capacity = hsm_capacity
        self.num_signatures = num_signatures
        self.kmip_batch_count = kmip_batch_count
        self.threaded = threaded

    def run(self, outfile: str) -> None:
        """
        Run this experiment. A server for the given API and HSM capacity will be started
        and the time taken for a client to perform the specified number of signatures
        will be measured and written to a file.

        :param outfile: the output file to use. The data will be written in CSV format
            with the field order: "api", "hsm_capacity", "num_signatures",
            "kmip_batch_count", "time", "threaded"
        """
        queue = multiprocessing.Queue()
        proc = multiprocessing.Process(target=self._start_server, args=(queue,))
        proc.start()
        # Wait until the server is set up
        _ = queue.get()
        # Sleep a short while to ensure the server is fully ready
        time.sleep(5)
        self._run_client(outfile)
        proc.kill()

    def _start_server(self, queue: multiprocessing.Queue) -> None:
        print(
            f"Starting {'threaded' if self.threaded else 'non-threaded'} "
            f"{self.api} server with HSM capacity {self.hsm_capacity} sigs/sec"
        )
        server_type = {
            "kmip": kmip_api.KMIPServer,
            "grpc": grpc_api.PKCS11gRPCServer,
            "rest": rest_api.PKCS11RESTServer,
        }

        hsm = mock_hsm.MockHSM(self.hsm_capacity, thread_safe=self.threaded)
        server = server_type[self.api](hsm, self.threaded)
        queue.put("ready")
        server.serve()

    def _run_client(self, outfile: str) -> None:
        print(
            f"Timing {self.num_signatures} signatures using a "
            f"{'threaded' if self.threaded else 'non-threaded' } {self.api} client"
            + (
                f" with batch count {self.kmip_batch_count}"
                if self.api == "kmip"
                else ""
            )
        )
        client_type = {
            "kmip": kmip_api.KMIPClient,
            "grpc": grpc_api.PKCS11gRPCClient,
            "rest": rest_api.PKCS11RESTClient,
        }

        client = client_type[self.api](self.threaded)

        if isinstance(client, kmip_api.KMIPClient):
            t = timeit.timeit(
                lambda: client.sign(
                    num_signatures=self.num_signatures,
                    batch_count=self.kmip_batch_count,
                ),
                number=1,
            )
        else:
            t = timeit.timeit(lambda: client.sign(self.num_signatures), number=1)

        print(f"Time taken for {self.num_signatures} signatures: {t}s")

        self._write_output(outfile, t)

    def _write_output(self, outfile: str, time: float) -> None:
        with open(outfile, "a") as f:
            fieldnames = [
                "api",
                "hsm_capacity",
                "num_signatures",
                "kmip_batch_count",
                "time",
                "threaded",
            ]

            writer = csv.DictWriter(f, fieldnames)
            writer.writerow(
                {
                    "api": self.api,
                    "hsm_capacity": self.hsm_capacity,
                    "num_signatures": self.num_signatures,
                    "kmip_batch_count": self.kmip_batch_count,
                    "time": time,
                    "threaded": self.threaded,
                }
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--experiments-file",
        help="JSON file to load the experiment configuration from",
        default="experiments.json",
    )
    parser.add_argument(
        "--output-file",
        help="File to append the resulting CSV data to",
        default="results.csv",
    )
    return parser.parse_args(sys.argv[1:])


def main():
    args = parse_args()
    with open(args.experiments_file) as f:
        exp_config = json.loads(f.read())

    jsonschema.validate(exp_config, experiments_schema)

    experiments = []
    for exp in exp_config["experiments"]:
        experiments.append(Experiment(**exp))

    repeat_count = exp_config.get("repeat")
    shuffle = exp_config.get("shuffle")
    total_runs = repeat_count * len(experiments)
    current_run = 0

    for i in range(repeat_count):
        if shuffle:
            random.shuffle(experiments)

        for exp in experiments:
            current_run += 1
            print(f"Starting experiment {current_run} out of {total_runs}")
            exp.run(args.output_file)


if __name__ == "__main__":
    main()
