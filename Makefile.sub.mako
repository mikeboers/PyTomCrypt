<%!

from os.path import exists

from setup import ext_names
from tomcrypt import meta

exts = ('pyx', 'pxd', 'pxi')

all_sources = {}
sources = {}
for name in ext_names:
	file_names = [name] + list(meta.ext_includes.get(name) or [])
	all_sources[name] = ['tomcrypt/%s.%s' % (name, ext) for ext in exts]
	for file_name in file_names:
		for ext in exts:
			all_sources[name].append('tomcrypt/%s.%s' % (file_name, ext))
			all_sources[name].append('tomcrypt/%s.%s.inc' % (file_name, ext))
	sources[name] = [x for x in all_sources[name] if exists(x) or exists(x + '.mako')]
			
	all_sources[name] = sorted(set(all_sources[name]))
	sources[name]     = sorted(set(sources[name]))

to_preprocess = []
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
   <% to_preprocess.append(source) %>
${source}: ${source}.mako
	$(PREPROCESS) -D ext_name=${name} $< > $@
  % endif
 % endfor

tomcrypt/${name}.c: ${' '.join(sources[name])}
	bin/cython tomcrypt/${name}.pyx

tomcrypt/${name}.so: $(LIBTOMCRYPT) tomcrypt/${name}.c
	env PyTomCrypt_ext_name=${name} $(PYTHON) setup.py build_ext --inplace

% endfor

preprocess: ${' '.join(to_preprocess)}

build: ${' '.join('tomcrypt/%s.so' % name for name in ext_names)}


clean:
% for name in ext_names:
 % for source in all_sources.get(name, []):
  % if exists(source + '.mako'):
	- rm ${source}
  % endif
 % endfor
% endfor
