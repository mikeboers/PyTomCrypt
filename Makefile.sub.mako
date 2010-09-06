<%!

from os.path import exists

from setup import ext_names
import meta

exts = ('pyx', 'pxd', 'pxi')

all_sources = {}
sources = {}
for name in ext_names:
	file_names = [name] + list(meta.ext_includes.get(name) or [])
	all_sources[name] = ['src/%s.%s' % (name, ext) for ext in exts]
	for file_name in file_names:
		for ext in exts:
			all_sources[name].append('src/%s.%s' % (file_name, ext))
			# all_sources[name].append('src/%s.%s.inc' % (file_name, ext))
	sources[name] = [x for x in all_sources[name] if exists(x) or exists(x + '.mako')]
			
	all_sources[name] = sorted(set(all_sources[name]))
	sources[name]	  = sorted(set(sources[name]))

to_preprocess = []
%>\
##
PYTHON = bin/python
PREPROCESS = ./preprocess
	
% for name in ext_names:
# Prep sources for "${name}".
 % for i, source in enumerate(sources[name]):
  % if exists(source + '.mako'):
build/${source}: ${source}.mako meta.py setup.py
	$(PREPROCESS) -D ext_name=${name} $< > $@
  % else:
build/${source}: ${source}
	cat $< > $@
  % endif
 % endfor

# Cross-compile "${name}".
src/${name}.c: ${' '.join('build/' + x for x in sources[name])}
	cython -o src/${name}.c build/src/${name}.pyx

# Compile "${name}".
tomcrypt/${name}.so: src/${name}.c
	env PyTomCrypt_ext_name=${name} $(PYTHON) setup.py build_ext --inplace

% endfor

preprocess: ${' '.join(to_preprocess)}

build: ${' '.join('tomcrypt/%s.so' % name for name in ext_names)}


clean:
% for name in ext_names:
 % for source in all_sources.get(name, []):
  % if exists(source) or exists(source + '.mako'):
	- rm build/${source}
  % endif
 % endfor
% endfor
