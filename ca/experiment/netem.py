import logging
import subprocess


def add_delay(delay_ms: int) -> None:
    logging.getLogger(__name__).debug(f"Adding {delay_ms}ms delay to eth0")
    subprocess.run(
        [
            "tc",
            "qdisc",
            "add",
            "dev",
            "eth0",
            "root",
            "netem",
            "delay",
            f"{delay_ms}ms",
        ]
    ).check_returncode()


def reset() -> None:
    logging.getLogger(__name__).debug("Removing netem rules")
    subprocess.run(
        [
            "tc",
            "qdisc",
            "del",
            "dev",
            "eth0",
            "root",
            "netem",
        ]
    ).check_returncode()
