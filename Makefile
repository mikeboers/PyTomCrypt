.PHONY: default build test clean

MODULE := $(shell python -c 'from __future__ import print_function; from tomcrypt.meta import *; print(module_name)')

default: build

build: $(MODULE)

$(MODULE): tomcrypt/_libtomcrypt.c
	python setup.py build_ext --inplace

test:
	python -m tests.runner -v --with-doctest --doctest-options '+ELLIPSIS'

clean: 
	- rm tomcrypt/*.so
	- rm tomcrypt/*.pyc
	- rm -rf dist
	- rm -rf build

