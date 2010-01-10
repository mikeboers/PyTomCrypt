
PYTHON = bin/python

default: test


_cipher.so: _cipher.pyx
	make -C libtomcrypt-1.16
	$(PYTHON) setup.py build_ext --inplace

build: _cipher.so

test: build
	$(PYTHON) cipher.py

clean:
	- rm *.o
	- rm *.so
	- rm -rf build