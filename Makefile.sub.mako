<%!

from os.path import exists

from setup import ext_names

%>
PYTHON = bin/python
PREPROCESS = ./preprocess
LIBTOMCRYPT = libtomcrypt-1.16

## Need to escape the "%" for mako's sake.
${'%'} : %.mako
	$(PREPROCESS) $< > $@


libtomcrypt : $(LIBTOMCRYPT)/libtomcrypt.a
$(LIBTOMCRYPT)/libtomcrypt.a : 
	make -C libtomcrypt-1.16
	

% for name in ext_names:
<%
exts = ('pyx', 'pxd', 'pxi')
src_name = dict(
	hmac='hash',
).get(name, name)
%>
% for ext in exts:
<%
src_path = 'tomcrypt/%s.%s.mako' % (src_name, ext)
dst_path = 'tomcrypt/%s.%s' % (name, ext)
%>
% if exists(src_path):
${dst_path}: ${src_path}
	$(PREPROCESS) -D ext_name=${name} $< > $@
% endif
% endfor
% if exists('tomcrypt/%s.pyx' % (name)) or exists('tomcrypt/%s.pyx.mako' % (src_name)):
<%
parents = ['tomcrypt/%s.%s' % (name, ext) for ext in exts]
parents = [x for x in parents if exists(x) or exists(x + '.mako')]
%>
tomcrypt/${name}.so: libtomcrypt ${' '.join(parents)}
	env PyTomCrypt_ext_name=${name} $(PYTHON) setup.py build_ext --inplace
% endif
% endfor


build: ${' '.join('tomcrypt/%s.so' % name for name in ext_names)}


test:
% for name in ext_names:
% if exists('tests/test_%s.py' % name):
	$(PYTHON) tests/test_${name}.py
% endif
% endfor


clean:
% for name in ext_names:
% for ext in ('pyx', 'pxd', 'pxi'):
% if exists('tomcrypt/%s.%s.mako' % (name, ext)):
	- rm tomcrypt/${name}.${ext}
% endif
% endfor
% endfor