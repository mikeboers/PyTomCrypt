
PYTHON = bin/python
MAKO = bin/mako-render

default : build

tomcrypt/hash.pyx : tomcrypt/hash.pyx.mako
	$(MAKO) $< > $@
	
tomcrypt/hmac.pyx : tomcrypt/hash.pyx.mako
	env PyTomCrypt_do_hmac=1 $(MAKO) $< > $@

tomcrypt/cipher.pyx : tomcrypt/cipher.pyx.mako
	$(MAKO) $< > $@
	
libtomcrypt :
	make -C libtomcrypt-1.16

tomcrypt/hmac.so tomcrypt/hash.so tomcrypt/cipher.so : tomcrypt/hmac.pyx tomcrypt/hash.pyx tomcrypt/cipher.pyx tomcrypt/common.pxi libtomcrypt
	$(PYTHON) setup.py build_ext --inplace

build: tomcrypt/cipher.so tomcrypt/hash.so tomcrypt/hmac.so

test: build
	$(PYTHON) tests/test_cipher.py
	$(PYTHON) tests/test_hash.py
	$(PYTHON) tests/test_hmac.py

clean:
	- rm *.o
	- rm *.so
	- rm -rf build
	- rm tomcrypt/*.c
	- rm tomcrypt/*.pyx
	- rm tomcrypt/*.so
