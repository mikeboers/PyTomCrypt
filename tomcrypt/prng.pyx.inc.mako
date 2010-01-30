
# Register all of the prngs.
# We don't really need to worry about doing this as they are needed as this
# doesn't take very long at all.
cdef int max_prng_idx = -1
% for name in prng_names:
max_prng_idx = max(max_prng_idx, register_prng(&${name}_desc))
% endfor
##

def test():
	"""Run the internal tests."""
	cdef int res
	% for name in prng_names:
	check_for_error(${name}_desc.test())
	% endfor
		
