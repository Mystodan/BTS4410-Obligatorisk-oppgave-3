import os
from SUCI_util import *
from cryptography import exceptions
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ENTITY_NAME_USER = "Daniel Hao Huynh"

cmd = cmd_arg([CMD_CONCEAL])

if cmd==None:
    err_print("\nNo valid command given.")
    sys.exit(1)


if cmd==CMD_CONCEAL:
    print("\nUser: Concealing a permanent identifier.")
    
    # Loading the Home Pubic key.
    home_pub_key = load_public_key(PUB_PEM)
    
    # generate ephemeral key-pair
    ephemeral_private_key, ephemeral_public_key = gen_ECDH_key_pair(ec.SECP256R1())
    
    # generate shared key
    dhs = ephemeral_private_key.exchange(ec.ECDH(),home_pub_key)
    
    # generating session key.
    session_key = key_derivation(dhs)
    
    # add length indicator and padding (as appropriate)
    # note: should check that the entity names have length <= 62 (*YOU ADD THAT*)
    utf8_home_ID = bytes(ENTITY_NAME_HOME,"utf-8")
    utf8_user_ID = bytes(ENTITY_NAME_USER,"utf-8")
    home_ID = add_padding(add_len_prefix(utf8_home_ID),64)
    user_ID = add_padding(add_len_prefix(utf8_user_ID),64)
    print("    Entity name home: '"+str(utf8_home_ID,"utf-8")+"'")
    print("    Entity name user: '"+str(utf8_user_ID,"utf-8")+"'")
    
    # serialization of ephemeral public key (w/length prefix)
    user_serialized_pub_key = add_len_prefix(serialize_pub_key(ephemeral_public_key))
   
    # using AEAD to encrypt/protect the "SUCI" information.   
    aesgcm = AESGCM(session_key) 
    IV = os.urandom(16)  
    aad = IV + home_ID + user_serialized_pub_key
    ct = aesgcm.encrypt(IV, user_ID, aad)
    
    SUCI_data = IV  +home_ID + user_serialized_pub_key + ct
    suci_file = open(SUCI_FILE_NAME,"wb")
    suci_file.write(SUCI_data)
    suci_file.close()
    print("    SUCI_data written to file. Len:",len(SUCI_data))
    
    print("User: Command completed.")
    sys.exit(0)
    

err_print("\nSomething went wrong:",cmd)
sys.exit(1)