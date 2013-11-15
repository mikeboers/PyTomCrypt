import os
import datetime

from distutils.core import setup
from distutils.extension import Extension


# RTD: Build the sources first.
on_rtd = os.environ.get('READTHEDOCS', None) == 'True'
if on_rtd:
    from subprocess import call
    call(['make', 'sources'])


# Allow us to specify a single extension to build.
ext_names = [
    '_core',
    'cipher',
    'hash',
    'mac',
    'prng',
    'rsa',
    'pkcs1',
    'pkcs5',
    'ecc',
    'utils',
]
ext_name = os.environ.get('PyTomCrypt_ext_name')
if ext_name:
    if ext_name not in ext_names:
        raise ValueError('unknown extension %r' % ext_name)
    ext_names = [ext_name]


ext_modules = []

# Define the extensions

for name in ext_names:

    ext_sources = []
    ext_source_spec = 'src/%s.ext_sources.txt' % name
    if os.path.exists(ext_source_spec):
        for line in open(ext_source_spec):
            line = line.strip()
            if line and not line.startswith('#'):
                ext_sources.append(line)

    ext_modules.append(Extension(
        'tomcrypt.%s' % name, ["tomcrypt/%s.c" % name] + ext_sources,

        include_dirs=[
                    '.',
                    './src',
                    './vendor/patched/libtomcrypt',
                    './vendor/libtomcrypt/src/headers',
                    './vendor/libtommath',
        ],

        define_macros=list(dict(
        
            # These macros are needed for the math library.
            LTM_DESC=None,
            LTC_SOURCE=None,
        
        ).items()),

        extra_compile_args=['-O3', '-funroll-loops', ]
    ))


# Go!
if __name__ == '__main__':
    setup(

        name='PyTomCrypt',
            description='Python+Cython wrapper around LibTomCrypt',
            version='0.10.0',
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
