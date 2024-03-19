#!/usr/bin/env python

import argparse
import atexit
import json
import logging
import sys
from pathlib import Path
from typing import Dict, List

import docker
from docker.types import Mount

import build
from experiment import Experiment
from util import AnsiCode, LogPrinter

CA_IMAGE_NAME = "experiment-ca"
HSM_IMAGE_NAME = "experiment-hsm"


def parse_args() -> argparse.Namespace:
    args = argparse.ArgumentParser()
    args.add_argument(
        "--experiments",
        help="JSON file with experiments to run",
        required=True,
        metavar="FILE",
    )
    args.add_argument(
        "--output-file",
        help="CSV for experiment results. Will be created if neccessary, "
        "otherwise results will be appended to the file",
        required=True,
        metavar="FILE",
    )
    args.add_argument(
        "--build", help="Build docker containers before running", action="store_true"
    )
    args.add_argument(
        "--runner-debug",
        help="Print debug output from the experiment runner",
        action="store_true",
    )
    args.add_argument(
        "--container-debug",
        help="Print debug output from the CA container script",
        action="store_true",
    )
    return args.parse_args(sys.argv[1:])


def set_up(
    client: docker.DockerClient, output_file: Path
) -> (docker.DockerClient, docker.DockerClient):
    network = client.networks.create("experiment_network")

    def clean_up():
        print(
            f"{AnsiCode.YELLOW}{AnsiCode.BOLD}Stopping all containers{AnsiCode.RESET}"
        )
        for container in client.containers.list():
            container.stop()
        network.remove()

    atexit.register(clean_up)

    hsm = client.containers.run(
        HSM_IMAGE_NAME,
        name="hsm",
        detach=True,
        remove=True,
        network=network.name,
        cap_add=["NET_ADMIN"],
    )
    LogPrinter(hsm.logs(stream=True), "hsm", AnsiCode.CYAN).start()

    ca = client.containers.run(
        CA_IMAGE_NAME,
        name="ca",
        detach=True,
        remove=True,
        network=network.name,
        cap_add=["NET_ADMIN"],
        mounts=[
            Mount(
                target="/experiment/results.csv",
                source=output_file.resolve().__str__(),
                type="bind",
            )
        ],
    )
    LogPrinter(ca.logs(stream=True), "ca", AnsiCode.PURPLE).start()

    return ca, hsm


def read_experiments(filename: str) -> List[Dict]:
    with open(filename) as f:
        json_data = json.loads(f.read())
        if "experiments" not in json_data:
            raise ValueError(f"{filename} is not a valid experiment file")
        return json_data["experiments"]


def find_or_create_output_file(filename: str) -> Path:
    output_file = Path(filename)
    if not (output_file.exists() and output_file.is_file()):
        logging.getLogger(__name__).debug("Creating output file")
        output_file.parent.mkdir(exist_ok=True, parents=True)
        output_file.touch()
    return output_file


def main():
    args = parse_args()
    if args.runner_debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("docker").setLevel(logging.WARNING)

    experiments = read_experiments(args.experiments)
    output_file = find_or_create_output_file(args.output_file)
    client = docker.client.from_env()

    if args.build:
        build.build(client, build.HSM_DOCKERFILE_PATH, HSM_IMAGE_NAME)
        build.build(client, build.CA_DOCKERFILE_PATH, CA_IMAGE_NAME)

    ca, hsm = set_up(client, output_file)

    for exp in experiments:
        Experiment(ca, hsm, debug=args.container_debug, **exp).run()


if __name__ == "__main__":
    main()
