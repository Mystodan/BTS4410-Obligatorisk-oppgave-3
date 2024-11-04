"""

"SUCI" utilities.

Some utility functions for the SUCI'ish scheme (Oppgave 3).
This 


"""
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash



PUB_PEM  = "ECDH_PUBLIC_KEY.PEM"
PRIV_PEM = "ECDH_PRIVATE_KEY.PEM"


CMD_KEYGEN = "KEYGEN"
CMD_CONCEAL = "CONCEAL"
CMD_DECONCEAL = "DECONCEAL"


SUCI_FILE_NAME = "SUCI_data.bin"


KDF_APP_INFO = bytes("BTS4410 -- Oppgave 3","utf-8")

# In SUCI this is a name used for routing the message back to Home.
ENTITY_NAME_HOME ="sidf@home.org" 


def cmd_arg(acceptable: list) -> str:
    """Check command-line args against 'acceptable' (list of strings).
    Not case sensitive. Will accept one (and only one) parameter.
    First match, no error checking, etc.
    If there is a mach, return the match. Otherwise, return None."""
    
    if len(acceptable)==0: return None      
    
    # the first parameter is the name of the program/script.
    # then comes the actual parameters.
    args = sys.argv
    if len(args) != 2: return None
    
    arg = args[1].upper()
    for accepted in acceptable:
        if accepted.upper() == arg:
            return(arg)
        
    return None


def err_print(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


#
# generate ECDH key-pair given the input curve
#
def gen_ECDH_key_pair(curve):
    """Our ECDH key-pair generation function. Return the key-pair tuple.
    The curve is one of ec.<curves> imported via
    'from cryptography.hazmat.primitives.asymmetric import ec'"""
       
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()    
    return private_key, public_key


def serialize_pub_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    

def store_public_key(public_key,filename):
    """This function serialized the public key and writes it to a PEM file.
    It also returns the serialized key."""
    serialized_public = serialize_pub_key(public_key)
    pem_pubf = open(filename,"wb")
    pem_pubf.write(serialized_public)
    pem_pubf.close()
    return serialized_public


def store_private_key(private_key,filename,pw):
    """This function serialized the private key and writes it to a PEM file.
    The PEM is encrypted with the password (pw).
    It also returns the serialized key."""
    serialized_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(pw)
    )
    pem_privf = open(filename,"wb")
    pem_privf.write(serialized_private)
    pem_privf.close()
    return serialized_private


def load_public_key(filename):
    """This function reads a PEM file containing the public key.
    The pem data is then de-seralized, and returned."""
    pem_pubf = open(filename,"rb")
    pem_pubkey_data = pem_pubf.read()
    pem_pubf.close()
    return(serialization.load_pem_public_key(pem_pubkey_data))
    

def load_private_key(filename, pw):
    """This function reads a PEM file containing the private key.
    The pem data is then de-seralized, and returned."""
    pem_privf = open(filename,"rb")
    pem_privkey_data = pem_privf.read()
    pem_privf.close()
    return(serialization.load_pem_private_key(pem_privkey_data,pw))


def key_derivation(dhs: bytes) -> bytes:
    return ConcatKDFHash(
        algorithm=hashes.SHA256(),length=16,
        otherinfo=KDF_APP_INFO
    ).derive(dhs)


def add_len_prefix(bytestr: bytes) -> bytes:
    length = len(bytestr)
    return length.to_bytes(2) +  bytestr


def add_padding(bytestr: bytes, length: int) -> bytes:
    """Add zero padding up to desired length."""
    bs_len = len(bytestr)
    assert bs_len<=length, "The bytestr exceeds the desired length: "+str(bs_len)
    zeroes = length-bs_len
    return bytestr + bytes(zeroes)