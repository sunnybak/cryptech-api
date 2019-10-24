import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder
import nacl.signing, nacl.hash
import os, hashlib

# creates nonce using seed
def create_nonce(nonce=None, seed=None):
    # seed is given
    if seed is not None:
        hashed_seed = hash_msg(seed)
        if seed == '': create_nonce(seed='0'*100) # empty seed will default to 100 zeros
        return str(bytes(hashed_seed, 'utf-8')[0:24].ljust(24, b'\0'),'utf-8') # create nonce from seed
    if nonce is not None:
        # given nonce of bytes, pick first 24 characters
        if type(nonce).__name__ == 'bytes':
            nonce = nonce[0:24].ljust(24, b'\0')
        # given nonce of string, pick first 24 characters and convert to bytes
        if type(nonce).__name__ == 'str':
            nonce = bytes(nonce[0:24].ljust(24, '\0'), 'utf-8')
    return nonce

# creates nacl.public.Box from private key and public key
def create_cipher(private_key, public_key):
    return Box(private_key, public_key)

# encrypt message with cipher and optionally nonce
def encrypt(msg, cipher, nonce=None):
    return cipher.encrypt(bytes(msg, 'utf-8'), # bytes of the message
                          encoder=nacl.encoding.HexEncoder, # define the encoder
                          nonce=create_nonce(nonce)).decode('utf-8') # give the nonce in utf-8

# decrypt message with cipher
def decrypt(msg, cipher):
    return cipher.decrypt(bytes(msg, 'utf-8'), # bytes of the message
                          encoder=nacl.encoding.HexEncoder).decode('utf-8') # define the encoder

# generate a fresh pair of private and public keys
def generate_keys():
    rk = PrivateKey.generate()
    uk = rk.public_key
    # keys must be hex encoded
    return {'private_key': nacl.encoding.HexEncoder.encode(bytes(rk)).decode('utf-8'),
            'public_key' : nacl.encoding.HexEncoder.encode(bytes(uk)).decode('utf-8')}

# computes the SHA-256 hash
def hash_msg(msg):
    return nacl.hash.sha256(bytes(msg, 'utf-8'), encoder=nacl.encoding.HexEncoder).decode('utf-8')

# computes the hash of a file given the file name
def file_hash(file_name):
    BLOCKSIZE = 65536 # block size = 64 kilobytes
    hasher = hashlib.sha256()
    # hashing the file in buckets
    with open(file_name, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return hasher.hexdigest()


def sign(msg, auth_rk, PUB_uk, nonce=None):
    auth_rk = PrivateKey(private_key=bytes(auth_rk, 'utf-8'), encoder=nacl.encoding.HexEncoder)
    return encrypt(msg, create_cipher(auth_rk, PUB_uk), nonce=create_nonce(nonce))

# verfies where the signature is valid
def verify(msg, sign, auth_pk):
    try:
        # convert plaintext pk to PublicKey type
        auth_pk = PublicKey(public_key=bytes(auth_pk, 'utf-8'), encoder=nacl.encoding.HexEncoder)
        return decrypt(sign.sign, create_cipher(sign.rk, auth_pk)) == msg # check if signature decrypts to msg
    except:
        return False

# nonce is contained in the first 48 characters of the sign
def verify_nonce(nonce, sign):
    sign = sign[0:48]
    # get nonce by creating
    nonce_sign = Sign(msg='0', auth_rk='0' * 64, nonce=create_nonce(nonce=nonce)).sign[0:48]
    # check if nonce is valid by reacreating it from signature
    return sign == nonce_sign

# signature object
class Sign(object):
    def __init__(self, msg=None, auth_rk=None, nonce=None, sign=None):
        self.create_properties()
        # initialize with sign or create new
        if sign:
            self.sign = sign
        else:
            # encode auth_rk
            auth_rk = PrivateKey(private_key=bytes(auth_rk, 'utf-8'), encoder=nacl.encoding.HexEncoder)
            # generate digital signature for message and author
            self.sign = encrypt(msg, create_cipher(auth_rk, self.uk), nonce=nonce)

    def __str__(self):
        return self.sign

    # initialize the class private keys
    @classmethod
    def create_properties(self):
        try:
            rk = os.environ.get('KNOWN_RK') or \
                 "d90cacd31e22c63ce99f062e88d6d2734e944e8d3dac895a67472701b6c55c7e"
            uk = os.environ.get('KNOWN_UK') or \
                "1a41da8aa64dc15e26e8ca787d35d559c10774d4a8e8c373418a0b0862f6567c"
        except:
            rk = 'd90cacd31e22c63ce99f062e88d6d2734e944e8d3dac895a67472701b6c55c7e'
            uk = '1a41da8aa64dc15e26e8ca787d35d559c10774d4a8e8c373418a0b0862f6567c'
        # encode the keys
        self.rk = PrivateKey(
            private_key=bytes(rk, 'utf-8'),
            encoder=nacl.encoding.HexEncoder)
        self.uk = PublicKey(
            public_key=bytes(uk, 'utf-8'),
            encoder=nacl.encoding.HexEncoder)
