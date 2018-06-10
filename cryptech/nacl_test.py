import nacl.utils
from nacl.public import PrivateKey, Box
from nacl.encoding import Base64Encoder
import nacl.signing, nacl.encoding, nacl.hash
import base64
import hashlib


def b(key): return nacl.encoding.HexEncoder.encode(bytes(key))

# Generate Shikhar's kr and ku
rk_S = PrivateKey(private_key=bytes('adcd19b7bf677cdd248754c22d04c557e6e1ee0f6c07b9282abfaaf980c4cdcd','utf-8'),encoder=nacl.encoding.HexEncoder)
uk_S = rk_S.public_key

print('S private key:',b(rk_S))
print('S public key:',b(uk_S))

print()

# Generate Matt's kr and ku
rk_M = PrivateKey.generate()
uk_M = rk_M.public_key

print('M private key:',b(rk_M))
print('M public key:',b(uk_M))


# S private key: b'adcd19b7bf677cdd248754c22d04c557e6e1ee0f6c07b9282abfaaf980c4cdcd'
# S public key: b'd32d42c2a9c228f6e1661b5060da9e683b39187483bf158c2c3f7143a4f17c71'
#
# M private key: b'3388c5a48435c1b5e935f2dcd7dbad0534f4f09fd18f79f65c8a91622f9a631c'
# M public key: b'4655530f50ae9a7ac608448c8da41c7ebf47cffb98dfcf0dcd69b208ec260b06'




print()

# print('Sending message from S to M:')
# cipher = Box(rk_S, uk_M)
#
# message = b"Hi M - from S"
# print('message plaintext: ' + str(message))
#
# encrypted = cipher.encrypt(message, encoder=nacl.encoding.HexEncoder)
# print("message ciphertext: "+ str(encrypted))
#
# decrypted = cipher.decrypt(encrypted, encoder=nacl.encoding.HexEncoder)
# print("decrypted message: "+ str(decrypted))
#
# print()
#
# print('Sending message from M to S:')
# cipher = Box(rk_M, uk_S)
#
# message = b"Hi S - from M"
# print('message plaintext: ' + str(message))
#
# encrypted = cipher.encrypt(message, encoder=nacl.encoding.HexEncoder)
# print("message ciphertext: "+ str(encrypted))
#
# decrypted = cipher.decrypt(encrypted, encoder=nacl.encoding.HexEncoder)
# print("decrypted message: "+ str(decrypted))
#
#
# print()
#
# print("Signing a message:")
#
# message = b"I am human"
# print('message plaintext: ' + str(message))
# hash_message = nacl.hash.sha256(message, encoder=nacl.encoding.HexEncoder)
# print('message hash: ' + str(hash_message))
# print()
# signing_key = nacl.signing.SigningKey.generate()
# print('Signing Key: ' + str(b(signing_key)))
#
#
# signed = signing_key.sign(message)
# signed_hash = signing_key.sign(hash_message)
# print('Signed Message: ' + str(b(signed)))
# print('Signed Hash: ' + str(b(signed_hash)))
#
#
# verify_key_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
# print('Verify Key: ' + str(verify_key_hex))
#
# print()
#
# print("Verifying a message:")
# verify_key = nacl.signing.VerifyKey(verify_key_hex, encoder=nacl.encoding.HexEncoder)
# try:
#     verify_key.verify(signed)
#     print('ok')
# except:
#     print('error')
#     exit(1)
#
#
