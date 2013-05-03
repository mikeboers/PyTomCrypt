import os
import datetime
import sys
from distutils.core import setup
from distutils.extension import Extension
from subprocess import Popen, call

# RTD: Build the sources first.
on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
if on_rtd:
    call(['make', 'sources'])


# Allow us to specify a single extension to build.
ext_names = ['_core', 'cipher', 'hash', 'mac', 'prng', 'rsa', 'pkcs1', 'pkcs5', 'ecc']
ext_name = os.environ.get('PyTomCrypt_ext_name')
if ext_name:
    if ext_name not in ext_names:
        raise ValueError('unknown extension %r' % ext_name)
    ext_names = [ext_name]


libtomcrypt = 'vendor/libtomcrypt/libtomcrypt.a'
if not os.path.exists(libtomcrypt):
    proc = Popen(['make'],
        cwd=os.path.dirname(libtomcrypt),
        env={'CFLAGS': '-DLTM_DESC -I../libtommath'},
        stdout=sys.stderr,
    )
    if proc.wait():
        print 'Could not build libtomcrypt'
        exit(1)

libtommath = 'vendor/libtommath/libtommath.a'
if not os.path.exists(libtommath):
    proc = Popen(['make'],
        cwd=os.path.dirname(libtommath),
        stdout=sys.stderr,
    )
    if proc.wait():
        print 'Could not build libtommath'
        exit(1)


# Define the extensions
ext_modules = [Extension(
    'tomcrypt.%s' % name, ["tomcrypt/%s.c" % name],

    extra_objects=[libtomcrypt, libtommath] if name == '_core' else [],

    include_dirs=[
                '.', # Buh?
                './src',
                './vendor/libtomcrypt/src/headers',
                './vendor/libtommath',
    ],

    define_macros=list(dict(
    
        # These macros are needed for the math library.
        LTM_DESC=None,
        LTC_SOURCE=None,
        # TFM_NO_ASM=None,
    
    ).items()),
) for name in ext_names]


# Go!
if __name__ == '__main__':
    setup(

        name='PyTomCrypt',
            description='Python+Cython wrapper around LibTomCrypt',
            version='0.7.0-dev',
            license='BSD-3',
            platforms=['any'],
            packages=['tomcrypt'],
            
            author='Mike Boers',
            author_email='pytomcrypt@mikeboers.com',
            maintainer='Mike Boers',
            maintainer_email='pytomcrypt@mikeboers.com',
            url='http://github.com/mikeboers/PyTomCrypt',
            

            classifiers = [
                'Development Status :: 4 - Beta',
                'Intended Audience :: Developers',
                'License :: OSI Approved :: BSD License',
                'Natural Language :: English',
                'Operating System :: OS Independent',
                'Programming Language :: C',
                'Programming Language :: Python :: 2',
                'Programming Language :: Python :: 3',
                'Topic :: Security :: Cryptography',
                'Topic :: Software Development :: Libraries :: Python Modules',
            ],

        ext_modules=ext_modules,
    )
