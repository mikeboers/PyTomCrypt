from tomcrypt import der, rsa, utils

print 'Generate a key...'
key = rsa.Key(1024)

print 'Encode to PEM...'
key_pem = key.as_string()

print 'Decode to DER...'
_, _, key_der = utils.pem_decode(key_pem)

print 'Decode the DER...'
der.pprint(key_der)

print 'Done.'
