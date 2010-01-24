
PYTHON = bin/python
PREPROCESS = ./preprocess
LIBTOMCRYPT = libtomcrypt-1.16
SUB = Makefile.sub
SUBMAKE = make -f $(SUB)

default : build

% : %.mako
	$(PREPROCESS) $< > $@

build: Makefile.sub
	$(SUBMAKE) build

test: build
	$(SUBMAKE) test

clean:
	- rm *.o
	- rm *.so
	- rm -rf build
	- rm Makefile.sub
	- rm tomcrypt/*.c
	- rm tomcrypt/*.pyx
	- rm tomcrypt/*.pxd
	- rm tomcrypt/*.so
