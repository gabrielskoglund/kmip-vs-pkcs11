import json
import os

import docker

from util import AnsiCode

CA_DOCKERFILE_PATH = os.path.join(os.path.dirname(__file__), "../ca/")
HSM_DOCKERFILE_PATH = os.path.join(os.path.dirname(__file__), "../hsm/")


def build(client: docker.DockerClient, path: str, tag: str):
    log = client.api.build(path=path, tag=tag)
    for line in log:
        status = json.loads(line)
        if "stream" in status:
            if status["stream"].strip() == "":
                continue
            print(
                f"{AnsiCode.YELLOW}Build {tag}: {status['stream'].strip()}{AnsiCode.RESET}"
            )
        elif "error" in status:
            print(
                f"{AnsiCode.RED}Build error: {status['error'].strip()}{AnsiCode.RESET}"
            )
