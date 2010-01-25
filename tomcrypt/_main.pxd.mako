<%

from os.path import exists
ext = 'pxd'

include_names = ext_includes.get(ext_name, [])
include_relpath = ['%s.%s.inc' % (x, ext) for x in include_names]
include_abspath = ['tomcrypt/%s.%s.inc' % (x, ext) for x in include_names]

%>
% for name, relpath, abspath in zip(include_names, include_relpath, include_abspath):
 % if exists(abspath) or exists(abspath + '.mako'):
include "${relpath}"
% endif
% endfor
