from tomcrypt import der, rsa, utils, Error

print 'RSA private key:'
key = rsa.Key(1024)
key_pem = key.as_string()
_, _, key_der = utils.pem_decode(key_pem)
der.pprint(key_der)
print

print 'RSA public key:'
key_pem = key.public.as_string()
_, _, key_der = utils.pem_decode(key_pem)
der.pprint(key_der)
print

print 'Malformed input 1:'
try:
    der.pprint('malformed')
except Error as e:
    print 'Caught %r' % e
print

print 'Malformed input 2:'
x = '0f3d52dccd8c3e25faab8b1c5bdd5b07b86c56484293cdca16bd2b168dd41cd133716f9a2474358ae4c946d5c3a21d1d0659840a15ff4809205913640eb121991149da648e25fc0b080c08001f00bd2e874cd18d0b249112e214c00251b697e5640543b137ff3e9c80daccbb39a41c284fc6f53321dca419a494292dcb9539bc'.decode('hex')
try:
    der.pprint(x)
except Error as e:
    print 'Caught %r' % e
print

print 'RSA signature:'
sig = key.sign('message')
sig_der = key.encrypt(sig, padding='none')
print len(sig_der), sig_der.encode('hex')
der.pprint(sig_der)
print