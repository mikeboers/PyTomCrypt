<%!

from os.path import exists

from setup import ext_names

exts = ('pyx', 'pxd', 'pxi')

sources = {}
for name in ext_names:
	sources[name] = ['tomcrypt/%s.%s' % (name, ext) for ext in exts]
	sources[name] = [x for x in sources[name] if exists(x) or exists(x + '.mako')]

%>\
##
PYTHON = bin/python
PREPROCESS = ./preprocess
LIBTOMCRYPT = libtomcrypt-1.16/libtomcrypt.a


$(LIBTOMCRYPT): 
	make -C libtomcrypt-1.16
	

% for name in ext_names:
 % for source in sources[name]:
  % if exists(source + '.mako'):
${source}: ${source}.mako
	$(PREPROCESS) -D ext_name=${name} $< > $@
  % endif
 % endfor
tomcrypt/${name}.so: $(LIBTOMCRYPT) ${' '.join(sources[name])}
	env PyTomCrypt_ext_name=${name} $(PYTHON) setup.py build_ext --inplace
% endfor


build: ${' '.join('tomcrypt/%s.so' % name for name in ext_names)}


clean:
% for name in ext_names:
 % for ext in ('pyx', 'pxd', 'pxi'):
  % if exists('tomcrypt/%s.%s.mako' % (name, ext)):
	- rm tomcrypt/${name}.${ext}
  % endif
 % endfor
% endfor
