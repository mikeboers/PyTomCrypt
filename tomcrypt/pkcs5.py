
import sys

from . import _main


self = sys.modules[__name__]

__all__ = _main.__pkcs5_all__
for name in __all__:
	setattr(self, name, getattr(_main, name))


_min_base_time = 1000 # Just needs to be higher than the test duration.
_BASE_TIME_ITERATIONS = 64
_BASE_TIME_TEST_COUNT = 3

def iterations_for_duration(duration):
    global _min_base_time
    # We always make a new test incase the machine is running faster.
    import timeit
    new_base_time = timeit.timeit(
        'pkcs5("password", "salt", iteration_count=%d)' % _BASE_TIME_ITERATIONS,
        'from %s import pkcs5' % __name__,
        number=_BASE_TIME_TEST_COUNT
    ) / _BASE_TIME_TEST_COUNT
    _min_base_time = min(_min_base_time, new_base_time)
    time_per_iteration = _min_base_time / _BASE_TIME_ITERATIONS
    return int(duration / time_per_iteration) + 1


if __name__ == '__main__':
    import timeit
    for i in range(10):
        n = iterations_for_duration(0.01)
        print n, timeit.timeit('pkcs5("password", "salt", iteration_count=%d)' % n, 'from %s import pkcs5' % __name__, number=10) / 10

