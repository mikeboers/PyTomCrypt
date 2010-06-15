
PyTomCrypt
==========

This project is a Python wrapper around LibTomCrypt.

Installation
------------

If you have the PyPi distribution, you only need run:

    $ python setup.py install

If you have the source:

1. Install "mako" and "cython"; they are required to generate the C
   source of the primary module.

2. Build the C source:
    
        $ make src/_main.c
    
3. Build the module:
    
        $ python setup.py build
    
4. Install the module:
    
        $ python setup.py install
