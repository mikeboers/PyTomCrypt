
PYTHON = bin/python
PREPROCESS = ./preprocess
LIBTOMCRYPT = libtomcrypt-1.16


default : build

tomcrypt/% : tomcrypt/%.mako
	$(PREPROCESS) $< > $@
	
libtomcrypt : $(LIBTOMCRYPT)/libtomcrypt.a
$(LIBTOMCRYPT)/libtomcrypt.a : 
	make -C libtomcrypt-1.16

tomcrypt/hash.so tomcrypt/cipher.so : tomcrypt/hash.pyx tomcrypt/cipher.pyx tomcrypt/cipher.pxd tomcrypt/common.pxi
	$(PYTHON) setup.py build_ext --inplace

build: libtomcrypt tomcrypt/cipher.so tomcrypt/hash.so

test: build
	$(PYTHON) tests/test_cipher.py
	$(PYTHON) tests/test_hash.py

clean:
	- rm *.o
	- rm *.so
	- rm -rf build
	- rm Makefile.sub
	- rm tomcrypt/*.c
	- rm tomcrypt/*.pyx
	- rm tomcrypt/*.pxd
	- rm tomcrypt/*.so
