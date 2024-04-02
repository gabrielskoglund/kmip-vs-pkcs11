import timeit

from src.mock_hsm import MockHSM

def test_hsm_signatures_per_second():
    # Ensure that the actual number of signatures per second
    # is within 5% of the specified number.
    for expected in [100, 1000, 10_000]:
        hsm = MockHSM(expected)
        t = timeit.timeit(hsm.sign, number=1000)
        actual = 1000 / t
        assert abs(actual / expected - 1) < 0.05

