
PYTHON = bin/python

default : build

hash.pyx : hash.pyx.mako
	mako-render $< > $@
	
hmac.pyx : hash.pyx.mako
	env PyTomCrypt_do_hmac=1 mako-render $< > $@

cipher.pyx : cipher.pyx.mako
	mako-render $< > $@
	
libtomcrypt :
	make -C libtomcrypt-1.16

hmac.so hash.so cipher.so : hmac.pyx hash.pyx cipher.pyx common.pxi libtomcrypt
	$(PYTHON) setup.py build_ext --inplace

build: cipher.so hash.so hmac.so

test: build
	$(PYTHON) test_cipher.py
	$(PYTHON) test_hash.py
	$(PYTHON) test_hmac.py

clean:
	- rm *.o
	- rm *.so
	- rm -rf build