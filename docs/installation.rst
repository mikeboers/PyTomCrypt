Installation
============

To get the latest stable release::

    $ pip install PyTomCrypt

.. note:: You can use ``easy_install`` if you don't have ``pip``.


If you already have the PyPi source distribution, you only need run::

    $ python setup.py install

If you have the original source (ie. from GitHub)::

    # Install "mako" and "cython"; they are required to generate the C source of the primary module.
    $ pip install mako cython
    
    # Grab libtomcrypt and libtommath.
    $ git submodule init
    $ git submodule update

    # Preprocess the Cython sources.
    $ make sources
    
    # Build the package.
    $ python setup.py build
    
    # Install the module.
    $ python setup.py install

