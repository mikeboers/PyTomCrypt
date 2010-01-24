
PYTHON = bin/python
PREPROCESS = ./preprocess
LIBTOMCRYPT = libtomcrypt-1.16
SUB = Makefile.sub
SUBMAKE = make -f $(SUB)

default : build

% : %.mako
	$(PREPROCESS) $< > $@

makesub: Makefile.sub

build: makesub
	$(SUBMAKE) build

test: build
	$(PYTHON) tests/test_cipher.py
	$(PYTHON) tests/test_hash.py
	$(PYTHON) tests/test_mac.py

clean:
	- rm *.o
	- rm *.so
	- rm *.pyc
	- rm -rf build
	- rm tomcrypt/*.c
	- rm tomcrypt/*.so
	- rm tomcrypt/*.pyc
	- $(SUBMAKE) clean
	- rm Makefile.sub
