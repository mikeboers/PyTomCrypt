
PYTHON = bin/python

default : build

cipher.pyx : cipher.pyx.mako
	mako-render cipher.pyx.mako > cipher.pyx

cipher.so : cipher.pyx
	make -C libtomcrypt-1.16
	$(PYTHON) setup.py build_ext --inplace

build: cipher.so

test: build
	$(PYTHON) test_cipher.py

clean:
	- rm *.o
	- rm *.so
	- rm -rf build