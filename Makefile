.PHONY: default build test clean

default: build

build:
	python setup.py build_ext --inplace

test: build
	nosetests

clean: 
	- rm tomcrypt/*.so
	- rm tomcrypt/*.pyc
	- rm -rf dist
	- rm -rf build

