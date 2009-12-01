from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

ext_modules = [Extension(
    "_crypto",
    ["_crypto.pyx"],
    include_dirs=['./libtomcrypt-1.16/src', './libtomcrypt-1.16/src/headers'],
    # library_dirs=['./libtomcrypt-1.16', './libtomcrypt-1.16/src'],
    # libraries=['./libtomcrypt-1.16/libtomcrypt.a'],
    extra_objects=['./libtomcrypt-1.16/libtomcrypt.a'],
)]

setup(
  name = 'pycrypto',
  cmdclass = {'build_ext': build_ext},
  ext_modules = ext_modules,
)
