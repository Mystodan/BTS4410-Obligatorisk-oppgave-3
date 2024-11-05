from SUCI_util import serialization, ec, key_derivation
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Constants
IV_LEN = 16
HOME_ID_LEN = 64
USER_PUB_LEN = 180
CT_LEN = 80

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
    IV = raw_suci_data[
          # Extracting the IV from RAW SUCI data.
          :IV_LEN # starts from index 0 to IV_LEN
          ]
    home_ID = raw_suci_data[
          # Extracting the Home ID from RAW SUCI data.
          IV_LEN:(home_id_end:=(IV_LEN+HOME_ID_LEN)) 
          #^ starts from IV_LEN to Byte Length of Home ID.
          ]
    user_serialized_pub_key = raw_suci_data[
          # Extracting the User Public Key from RAW SUCI data.
          home_id_end:(u_sr_pbkey_end:=home_id_end+ USER_PUB_LEN) 
          #^ starts from Byte Length of Home ID to Byte Length of User Public Key.
          ]
    ct = raw_suci_data[
          # Extracting the ciphertext from RAW SUCI data.
          u_sr_pbkey_end:(u_sr_pbkey_end+CT_LEN)
          #^ starts from Byte Length of User Public Key to the end of the RAW SUCI data.
          ]
    # Recreating the AESGCM object in order to decrypt it from the concealed data.
    aegcm = AESGCM(key_derivation(priv_key.exchange(ec.ECDH(),deserialize_pub_key(user_serialized_pub_key))))
    aad = IV + home_ID + user_serialized_pub_key # Additional authenticated data.
    
    # Extracting the Home ID and User ID.
    ## Removing the padding and slicing the length prefix.
    home_ID = slice_len_prefix(remove_padding(home_ID))
    user_ID = slice_len_prefix(remove_padding(aegcm.decrypt(IV, ct, aad)))
    ## Decoding the bytes to string.
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