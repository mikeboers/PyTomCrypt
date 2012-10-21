import sys

def main():
    import doctest
    import nose.core
    
    # Monkey-patch doctest to remove "b" prefix from strings in Python 2.
    old = doctest.DocTestFinder.find
    def new(self, *args, **kwargs):
        tests = old(self, *args, **kwargs)    
        if sys.version_info.major < 3:
            for test in tests:
                for example in test.examples:
                    if example.want.startswith("b'"):
                        example.want = example.want[1:]
        return tests
    doctest.DocTestFinder.find = new

    nose.core.main()


if __name__ == '__main__':
    main()
