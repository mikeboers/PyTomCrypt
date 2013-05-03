PYTHON = bin/python
PREPROCESS = ./preprocess

MOD_NAMES = _core cipher ecc hash mac pkcs1 pkcs5 prng rsa
SO_NAMES = $(MOD_NAMES:%=tomcrypt/%.so)
C_NAMES = $(MOD_NAMES:%=tomcrypt/%.c)

MAKO_SRCS := $(wildcard src/*.pyx) $(wildcard src/*.pxd)
CYTHON_SRCS = $(MAKO_SRCS:src/%=build/src/tomcrypt.%)

# VERSION := $(shell python setup.py --version)
REMOTE_DOCS_HOST = mikeboers.com
REMOTE_DOCS_PATH = /srv/mikeboers.com/docs/pytomcrypt

.PHONY : default build test readme clean clean-all docs

default : build

# Evaluating Mako templates.
build/src/tomcrypt.%: src/%
	@ mkdir -p build/src
	./preprocess $< > $@

# Translating Cython to C.
tomcrypt/%.c: build/src/tomcrypt.%.pyx
	cython -o $@.tmp $<
	mv $@.tmp $@

# Requirements for the core.
build/src/tomcrypt._core.c: $(filter %-core.pxd,$(CYTHON_SRCS))

sources: $(CYTHON_SRCS) $(C_NAMES)

build: $(CYTHON_SRCS) $(C_NAMES)
	python setup.py build_ext --inplace

test: build
	nose2

readme: README.html

README.html: README.md
	markdown $< > $@

clean: 
	- rm tomcrypt/*.so
	- rm tomcrypt/*.pyc
	- rm -rf dist
	- rm -rf build/src build/*/tomcrypt

clean-all: clean
	- rm -rf build
	- make -C vendor/libtomcrypt clean
	- make -C vendor/libtommath clean

docs: build
	PYTHONPATH=.. make -C docs html

deploy-docs: docs
	rsync -avx docs/_build/html/ ${REMOTE_DOCS_HOST}:${REMOTE_DOCS_PATH}/${VERSION}
	ssh ${REMOTE_DOCS_HOST} ln -sf ${REMOTE_DOCS_PATH}/${VERSION} ${REMOTE_DOCS_PATH}/latest




