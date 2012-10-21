import sys
import doctest


def fix_doctests(suite):
    if sys.version_info.major >= 3:
        return
    for case in suite._tests:
        # Add some more flags.
        case._dt_optionflags = (
            (case._dt_optionflags or 0) |
            doctest.IGNORE_EXCEPTION_DETAIL |
            doctest.ELLIPSIS |
            doctest.NORMALIZE_WHITESPACE
        )
        test = case._dt_test
        for example in test.examples:
            # Remove b prefix from strings.
            if example.want.startswith("b'"):
                example.want = example.want[1:]


def get_doctests(mod):
    suite = doctest.DocTestSuite(mod)
    fix_doctests(suite)
    return suite

