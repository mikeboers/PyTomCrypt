
PYTHON = bin/python
PREPROCESS = ./preprocess
LIBTOMCRYPT = libtomcrypt-1.16
SUB = Makefile.sub
SUBMAKE = make -f $(SUB)

default : build

% : %.mako
	$(PREPROCESS) $< > $@

submake: Makefile.sub

preprocess: submake
	$(SUBMAKE) preprocess

build: submake
	mkdir -p build/src
	$(SUBMAKE) build

src/_main.c: submake
	mkdir -p build/src
	$(SUBMAKE) src/_main.c

test: build
	$(PYTHON) tests/test_cipher.py
	$(PYTHON) tests/test_hash.py
	$(PYTHON) tests/test_mac.py
	$(PYTHON) tests/test_prng.py
	$(PYTHON) tests/test_rsa.py

cleanbuild:	
	- rm -rf build

clean: submake
	- rm *.o
	- rm *.so
	- rm *.pyc
	- rm src/_main.c
	- rm tomcrypt/*.c
	- rm tomcrypt/*.so
	- rm tomcrypt/*.pyc
	- rm -rf dist
	- $(SUBMAKE) clean
	- rm Makefile.sub

cleanall: clean cleanbuild

cleantest:
	make clean
	make test
