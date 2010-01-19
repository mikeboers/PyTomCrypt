
PYTHON = bin/python
MAKO = bin/mako-render
LIBTOMCRYPT = libtomcrypt-1.16


default : build

tomcrypt/% : tomcrypt/%.mako
	$(MAKO) $< > $@
	
tomcrypt/hmac.pyx : tomcrypt/hash.pyx.mako
	env PyTomCrypt_do_hmac=1 $(MAKO) $< > $@
	
libtomcrypt : $(LIBTOMCRYPT)/libtomcrypt.a
$(LIBTOMCRYPT)/libtomcrypt.a : 
	make -C libtomcrypt-1.16

tomcrypt/hmac.so tomcrypt/hash.so tomcrypt/cipher.so : tomcrypt/hmac.pyx tomcrypt/hash.pyx tomcrypt/cipher.pyx tomcrypt/common.pxi
	$(PYTHON) setup.py build_ext --inplace

build: libtomcrypt tomcrypt/cipher.so tomcrypt/hash.so tomcrypt/hmac.so

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
