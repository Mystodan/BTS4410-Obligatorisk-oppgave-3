import os, sys
from SUCI_util import *
from cryptography import exceptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PRIVPW   = bytes("BTS4410 Høsten 2024","utf-8")

cmd = cmd_arg([CMD_KEYGEN,CMD_DECONCEAL])

if cmd==None:
    err_print("\nNo valid command given.")
    sys.exit(1)


if cmd==CMD_KEYGEN:
    print("\nHome: Generating long-term ECDH key-pair.")
    private_key, public_key = gen_ECDH_key_pair(ec.SECP256R1())
    
    print("    Key-pair generated.")
    
    len_priv_pem = len(store_private_key(private_key,PRIV_PEM,PRIVPW))
    print("    Private key stored in pem-file. Filesize:", len_priv_pem)
    
    len_pub_pem = len(store_public_key(public_key,PUB_PEM))
    print("    Public key stored in pem-file.  Filesize:", len_pub_pem)    
    
    print("Home: Command completed.")
    sys.exit(0)
    

if cmd==CMD_DECONCEAL:

    def deserialize_pub_key(serialized_public_key):
        return serialization.load_pem_public_key(serialized_public_key)

    def slice_len_prefix(bytestr: bytes) -> bytes:
        """Slice off the length prefix and return the length and the rest."""
        length = int.from_bytes(bytestr[:2],"big")
        return bytestr[2:]

    def remove_padding(bytestr: bytes) -> bytes:
        """Remove zero padding."""
        return bytestr.rstrip(b'\0')

    print("\nHome: Deconceal command given.")


    priv_key = load_private_key(PRIV_PEM, PRIVPW)
    print("    Loaded own private key. Size:",priv_key.key_size)


    f = open(SUCI_FILE_NAME,"rb")
    raw_suci_data = f.read()
    print("    Loaded: "+SUCI_FILE_NAME+", Length:",len(raw_suci_data))

    IV = raw_suci_data[:16]
    home_ID = (raw_suci_data[16:(home_id_end:=(64+16))])
    user_serialized_pub_key = raw_suci_data[home_id_end:(sr_pbkey_end:=180+64+16)]
    ct = raw_suci_data[sr_pbkey_end:]
    
    aegcm = AESGCM(key_derivation(priv_key.exchange(ec.ECDH(),deserialize_pub_key(user_serialized_pub_key))))
    aad = IV + home_ID + user_serialized_pub_key
    
    
    home_ID = slice_len_prefix(remove_padding(home_ID))
    user_ID = slice_len_prefix(remove_padding(aegcm.decrypt(IV, ct, aad)))
    home_ID = str(home_ID,"utf-8")
    user_ID = str(user_ID,"utf-8")

    ct = aegcm.decrypt(IV, ct, aad)
    ct = str(ct,"utf-8")
    SUCI_data = ''.join([(f"\tIV:{IV}\n"),
    (f"\tHome ID:{home_ID}\n"),
    (f"\tUser ID:{user_ID}\n")])

    with open("SUCI_data.txt","w",encoding='utf-8') as f:
        f.write(SUCI_data)

    print("    SUCI_data written to file. Len:",len(SUCI_data))
    

    print("Home: Command completed.")    
    sys.exit(0)


err_print("\nSomething went wrong:", cmd)
sys.exit(1)
