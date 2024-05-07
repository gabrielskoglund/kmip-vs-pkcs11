import threading
import logging
import time
import timeit


class MockHSM:
    """
    MockHSM provides a basic interface emulating a HSM performing
    constant time signing operations.

    :param signatures_per_second: the desired signing capability
        of the HSM in terms of signatures per second.
    :thread_safe: a boolean indicating if this HSM should be safe
        to access from multiple threads. In that case,
        the `sign` operation will use locking to ensure that
        it cannot be used by more than one thread at a time.
    """

    def __init__(self, signatures_per_second: int, thread_safe: bool = False):
        self.log = logging.getLogger(self.__class__.__name__)
        self.signatures_per_second = signatures_per_second
        self.thread_safe = thread_safe
        if thread_safe:
            self.lock = threading.Lock()
        self._tune_delay()

    def sign(self) -> None:
        """
        Perform a mock signing operation, simply delaying for a constant
        amount of time.
        """
        if self.thread_safe:
            self.lock.acquire()
            self._sleep(self.delay_s)
            self.lock.release()
        else:
            self._sleep(self.delay_s)

    def _tune_delay(self) -> None:
        """
        Attempt to tune the delay for each signing operation so that
        the desired number of signatures per seconds is achieved.
        """
        self.log.debug(
            f"Tuning HSM delay with target {self.signatures_per_second}"
            " signatures per second, this may take a little while..."
        )
        # Set an initial best guess for delay to use
        self.delay_s = 1 / self.signatures_per_second
        t = 0
        while abs(t - 1) > 0.01:
            t = timeit.timeit(lambda: self.sign(), number=self.signatures_per_second)
            # Update delay based on how far from the target we were
            self.delay_s *= 1 / t
        self.log.debug("HSM delay tuning done")

    def _sleep(self, duration: float) -> None:
        """
        Sleep for the given duration (in seconds).
        Benchmarking the performance of this function has shown that
        it has better granularity than time.sleep.
        """
        now = time.perf_counter()
        end = now + duration
        while now < end:
            now = time.perf_counter()
