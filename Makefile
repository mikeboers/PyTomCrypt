
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
	$(SUBMAKE) test

clean:
	- rm *.o
	- rm *.so
	- rm -rf build
	- rm tomcrypt/*.c
	- rm tomcrypt/*.so
	- $(SUBMAKE) clean
	- rm Makefile.sub
