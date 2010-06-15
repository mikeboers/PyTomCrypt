'''Tests to determine the models for time performance of pkcs5.

It appears as though pkcs5 is linear with respect to number of iteractions,
and constant with respect to password/salt length.


'''


import os
import timeit

setup = '''

from tomcrypt.pkcs5 import pkcs5

password = %r
salt = %r

'''

source = '''

pkcs5(password, salt, iteration_count=%d)

'''


print '(* Variable iteration count:'
data = []
for i in range(1, 8):
    n = 2**i
    data_point = (n, timeit.timeit(source % n, setup % (os.urandom(8), os.urandom(16)), number=100))
    data.append(data_point)
    print '\t%d -> %f' % data_point
print '*)'
print 'data = {%s}' % ', '.join('{%d, %f}' % x for x in data)

print '(* Variable password length:'
data = []
for i in range(1, 20):
    n = 2 * i
    data_point = (n, timeit.timeit(source % 64, setup % (os.urandom(n), os.urandom(16)), number=100))
    data.append(data_point)
    print '\t%d -> %f' % data_point
print '*)'
print 'data = {%s}' % ', '.join('{%d, %f}' % x for x in data)

print '(* Variable salt length:'
data = []
for i in range(1, 20):
    n = 4 * i
    data_point = (n, timeit.timeit(source % 64, setup % (os.urandom(8), os.urandom(n)), number=100))
    data.append(data_point)
    print '\t%d -> %f' % data_point
print '*)'
print 'data = {%s}' % ', '.join('{%d, %f}' % x for x in data)