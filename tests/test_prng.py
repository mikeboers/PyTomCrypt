from tomcrypt import prng

def test_library():
    prng.test_library()

def test_seeds():
    
    x = prng.fortuna()
    x.add_entropy('12345678')
    # print x.read(16).encode('hex')
    assert x.read(16).encode('hex') == 'b1f2630e4b56ff6f1e0e5d6f1324a10d'
    
    x = prng.rc4()
    x.add_entropy('12345678')
    # print x.read(16).encode('hex')
    assert x.read(16).encode('hex') == '0a015ada42e721c8ee3d57a0b519a9a8'
    
    x = prng.sober128()
    x.add_entropy('12345678')
    # print x.read(16).encode('hex')
    assert x.read(16).encode('hex') == '39e10e5ccaa9a24c26abaf73dbf2e3f6'
    
    x = prng.yarrow()
    x.add_entropy('12345678')
    # print x.read(16).encode('hex')
    assert x.read(16).encode('hex') == 'f63c36f72ad5098e42ac002243d2cce2'