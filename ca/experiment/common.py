from abc import ABC, abstractmethod
import logging

# TODO: replace this data with a proper tbs cert (or several)
DATA = b"Hello there!"


class Protocol(ABC):
    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)
        self.session = None
        self.private_key = None
        self.public_key = None
        self.set_up_complete = False

    @abstractmethod
    def set_up(self) -> None:
        pass

    @abstractmethod
    def run_tests(self) -> None:
        pass


class ProtocolNotSetUpException(Exception):
    pass
