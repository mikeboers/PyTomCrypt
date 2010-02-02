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
/include
/lib
/pip-log.txt
/MANIFEST

*.o
*.a

/libtomcrypt-1.16
/libtommath-0.39
/tomsfastmath-0.10

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