.PHONY: default build test clean

MODULE := $(shell python -c 'from tomcrypt.meta import *; print module_name')

default: build

build: $(MODULE)

$(MODULE): tomcrypt/_libtomcrypt.c
	python setup.py build_ext --inplace

test:
	nosetests -v --with-doctest

clean: 
	- rm tomcrypt/*.so
	- rm tomcrypt/*.pyc
	- rm -rf dist
	- rm -rf build

