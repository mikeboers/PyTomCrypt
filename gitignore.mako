<%!

from os.path import exists

%>

# General
*.pyc
.DS_Store

# virtualenv
/.Python
/bin
/build
/dist
/include/python2.6
/lib/python2.6
/pip-log.txt
/MANIFEST

/src/libtomcrypt-1.16/doc/crypt.pdf
*.o
*.a

/gitignore
/Makefile.sub

# Build
% for ext in ext_includes:
/tomcrypt/${ext}.so
/tomcrypt/${ext}.c
% endfor

% for ext, includes in ext_includes.items():
% for name in [ext] + includes:
% for ext in 'pyx pxd pxi inc pyx.inc pxd.inc pxi.inc'.split():
## ${name} ${ext}
% if exists('tomcrypt/%s.%s.mako' % (name, ext)):
/tomcrypt/${name}.${ext}
% endif
% endfor
% endfor
% endfor