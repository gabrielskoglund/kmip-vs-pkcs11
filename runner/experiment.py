import logging

from docker.models.containers import Container

from util import AnsiCode, LogPrinter


class Experiment:
    """
    The Experiment class provides an interface for executing experiments in the
    CA docker container.
    """

    def __init__(
        self,
        ca: Container,
        hsm: Container,
        protocol: str,
        rtt_ms: int = 0,
        kmip_batch_size: int = None,
        debug: bool = False,
    ):
        self.log = logging.getLogger(self.__class__.__name__)
        self.ca = ca
        self.hsm = hsm
        self.protocol = protocol
        self.rtt_ms = rtt_ms
        self.kmip_batch_size = kmip_batch_size
        self.debug = debug

    def run(self):
        self.set_rtt()

        _, log = self.ca.exec_run(
            f"/experiment/main.py --protocol {self.protocol} "
            f"{'--debug' if self.debug else ''} "
            f"--rtt {self.rtt_ms} "
            + (
                f"--kmip-batch-size {self.kmip_batch_size}"
                if self.kmip_batch_size
                else ""
            ),
            stream=True,
        )
        LogPrinter(log, "ca", AnsiCode.PURPLE).run()

        self.reset_netem_settings()

    def set_rtt(self):
        delay = self.rtt_ms / 2
        self.log.debug(f"Adding {delay}ms delay to eth0 of CA container")
        exit_code, _ = self.ca.exec_run(
            f"tc qdisc add dev eth0 root netem delay {delay}ms"
        )
        if exit_code != 0:
            raise RuntimeError("Failed to set delay on CA container")

        self.log.debug(f"Adding {delay}ms delay to eth0 of HSM container")
        exit_code, _ = self.hsm.exec_run(
            f"tc qdisc add dev eth0 root netem delay {delay}ms"
        )
        if exit_code != 0:
            raise RuntimeError("Failed to set delay on HSM container")

    def reset_netem_settings(self):
        self.log.debug("Resetting netem settings of CA container")
        exit_code, _ = self.ca.exec_run("tc qdisc del dev eth0 root netem")
        if exit_code != 0:
            raise RuntimeError("Failed to remove netem settings on CA container")

        self.log.debug("Resetting netem settings of HSM container")
        exit_code, _ = self.hsm.exec_run("tc qdisc del dev eth0 root netem")
        if exit_code != 0:
            raise RuntimeError("Failed to remove netem settings on CA container")
