import os

from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext


# Allow us to specify a single extension to build.
ext_names = ['cipher', 'hash']
ext_name = os.environ.get('PyTomCrypt_ext_name')
if ext_name:
	if ext_name not in ext_names:
		raise ValueError('unknown extension %r' % ext_name)
	ext_names = [ext_name]


# Define the extensions
ext_modules = [Extension(
    'tomcrypt.%s' % name, ["tomcrypt/%s.pyx" % name],
    include_dirs=['./libtomcrypt-1.16/src/headers'],
    extra_objects=['./libtomcrypt-1.16/libtomcrypt.a'],
) for name in ext_names]


# Go!
if __name__ == '__main__':
	setup(
	  name = 'PyTomCrypt',
	  cmdclass = {'build_ext': build_ext},
	  ext_modules = ext_modules,
	)
