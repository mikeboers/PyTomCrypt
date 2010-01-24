from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

ext_names = ['cipher', 'hash']

ext_modules = [Extension(
    'tomcrypt.%s' % name,
    ["tomcrypt/%s.pyx" % name],
    include_dirs=['./libtomcrypt-1.16/src/headers'],
    extra_objects=['./libtomcrypt-1.16/libtomcrypt.a'],
) for name in ext_names]

setup(
  name = 'PyTomCrypt',
  cmdclass = {'build_ext': build_ext},
  ext_modules = ext_modules,
)
