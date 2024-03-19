from threading import Thread
from typing import Generator


class AnsiCode:
    RED = "\033[0;91m"
    YELLOW = "\033[0;93m"
    PURPLE = "\033[0;95m"
    CYAN = "\033[0;96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


class LogPrinter(Thread):
    def __init__(
        self, log_source: Generator[bytes, None, None], name: str, color: AnsiCode
    ):
        super().__init__(daemon=True)
        self.log = log_source
        self.name = name
        self.color = color

    def run(self):
        for msg in self.log:
            for line in msg.decode("utf-8").split("\n"):
                if not line.strip() == "":
                    print(
                        f" {self.color}{self.name:<3} | {AnsiCode.RESET}"
                        f"{line.strip()}"
                    )
