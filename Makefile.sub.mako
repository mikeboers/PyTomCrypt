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
parents = ['tomcrypt/%s.%s' % (name, ext) for ext in ('pyx', 'pxd', 'pxi')]
parents = [x for x in parents if exists(x) or exists(x + '.mako')]
%>
tomcrypt/${name}.so: libtomcrypt ${' '.join(parents)}
	env PyTomCrypt_ext_name=${name} $(PYTHON) setup.py build_ext --inplace
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