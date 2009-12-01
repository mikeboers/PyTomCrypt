
PYTHON = bin/python

default: test


_crypto.so: _crypto.pyx
	make -C libtomcrypt-1.16
	$(PYTHON) setup.py build_ext --inplace

build: _crypto.so

test: build
	$(PYTHON) crypto.py

clean:
	- rm *.o
	- rm *.so
	- rm -rf build