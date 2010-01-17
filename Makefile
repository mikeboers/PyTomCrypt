
PYTHON = bin/python

default : build

hash.pyx : hash.pyx.mako
	mako-render $< > $@

cipher.pyx : cipher.pyx.mako
	mako-render $< > $@
	
libtomcrypt :
	make -C libtomcrypt-1.16

hash.so cipher.so : hash.pyx cipher.pyx common.pxi libtomcrypt
	$(PYTHON) setup.py build_ext --inplace

build: cipher.so hash.so

test: build
	$(PYTHON) test_cipher.py
	$(PYTHON) test_hash.py

clean:
	- rm *.o
	- rm *.so
	- rm -rf build