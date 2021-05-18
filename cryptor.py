from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encryption(data, key):
    iv = os.urandom(16)
    cipher = Cipher(
        algorithms.AES(key), 
        modes.CBC(iv), 
        backend=default_backend()
        )
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    cipherdata = padder.update(data)
    cipherdata += padder.finalize()
    cipherdata = encryptor.update(cipherdata)
    cipherdata += encryptor.finalize()
    return iv + cipherdata

def decryption(cipherdata, key):
    cipher = Cipher(
        algorithms.AES(key), 
        modes.CBC(cipherdata[:16]), 
        backend=default_backend()
        )
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    data = decryptor.update(cipherdata[16:])
    data += decryptor.finalize()
    data = unpadder.update(data)
    data += unpadder.finalize()
    return data