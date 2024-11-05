from SUCI_util import serialization, ec, key_derivation
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
def deserialize_pub_key(serialized_public_key):
        """Deserialize the public key."""
        return serialization.load_pem_public_key(serialized_public_key)

def slice_len_prefix(bytestr: bytes) -> bytes:
        """Slice off the length prefix and return the length and the rest."""
        return bytestr[2:]

def remove_padding(bytestr: bytes) -> bytes:
        """Remove zero padding."""
        return bytestr.rstrip(b'\0')

def deconceal(priv_key: ec.EllipticCurvePrivateKey, raw_suci_data: bytes, path = "./", savefile=True) -> bytes:
    """This function deconceals the SUCI data."""
    # Extracting the IV, Home ID, User ID, and the ciphertext.
    IV = raw_suci_data[:16]
    home_ID = (raw_suci_data[16:(home_id_end:=(64+16))])
    user_serialized_pub_key = raw_suci_data[home_id_end:(sr_pbkey_end:=180+64+16)]
    ct = raw_suci_data[sr_pbkey_end:]
    # Creating the AESGCM object in order to remove it from the concealed data.
    aegcm = AESGCM(key_derivation(priv_key.exchange(ec.ECDH(),deserialize_pub_key(user_serialized_pub_key))))
    aad = IV + home_ID + user_serialized_pub_key # Additional authenticated data.
    
    # Extracting the Home ID and User ID.
    home_ID = slice_len_prefix(remove_padding(home_ID))
    user_ID = slice_len_prefix(remove_padding(aegcm.decrypt(IV, ct, aad)))
    home_ID = str(home_ID,"utf-8")
    user_ID = str(user_ID,"utf-8")
    # Decryption of the ciphertext.
    ct = aegcm.decrypt(IV, ct, aad)
    ct = str(ct,"utf-8")
    SUCI_data = ''.join([(f"\tIV:{IV}\n"),
    (f"\tHome ID:{home_ID}\n"),
    (f"\tUser ID:{user_ID}\n")])
    # Saving the SUCI data to a file.
    if savefile:
        with open(f"{path}SUCI_data.txt","w",encoding='utf-8') as f:
            f.write(SUCI_data)

    print("    SUCI_data written to file. Len:",len(SUCI_data))
    return SUCI_data, home_ID, user_ID # Returning the SUCI data, Home ID, and User ID.