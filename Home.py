import os, sys
from SUCI_util import *
from cryptography import exceptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from deconceal import deconceal

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



    print("\nHome: Deconceal command given.")


    priv_key = load_private_key(PRIV_PEM, PRIVPW)
    print("    Loaded own private key. Size:",priv_key.key_size)

    
    f = open(SUCI_FILE_NAME,"rb")
    raw_suci_data = f.read()
    print("    Loaded: "+SUCI_FILE_NAME+", Length:",len(raw_suci_data))
    ###### Implemented code for deconcealing the SUCI data.######
    data, _, _ = deconceal(priv_key, raw_suci_data) 
    print(data)
    #############################################################
    print("Home: Command completed.")    
    sys.exit(0)


err_print("\nSomething went wrong:", cmd)
sys.exit(1)
