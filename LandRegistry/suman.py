import hashlib

def hash(data):
        '''Compute the SHA-512 hash and return the result as hex characters.'''
        return hashlib.sha512(data).hexdigest()
a=hash("suman".encode('utf-8'))[0:64]
b=hash("suman".encode('utf-8'))[0:64]
print(a)
print(b)
