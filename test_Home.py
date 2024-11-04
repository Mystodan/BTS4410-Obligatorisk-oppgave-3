# Home.py
import unittest
from extract_tests import getTestData, TEST_SET, TEST_DIRECTORY, getFolderNames
from SUCI_util import  load_private_key, ENTITY_NAME_HOME
from deconceal import deconceal
from shutil import rmtree

DELETE_FOLDER = True

class TestHome(unittest.TestCase):
    def test_deconceal(self):
        """Test the deconceal function."""  
        SUCI_FILE_NAME = "SUCI_data.bin"
        PRIV_PEM = "ECDH_PRIVATE_KEY.PEM"
        PRIVPW = bytes("BTS4410 Høsten 2024","utf-8")
        ENTITY_NAME_USER = "privacy-sensitive-name ÆØÅ"
        getTestData(*TEST_SET)
        testfolders = getFolderNames() 
        for folder in testfolders:
            with open(f"{TEST_DIRECTORY}{folder}/{SUCI_FILE_NAME}","rb") as f:
                raw_suci_data = f.read()
                      
            print("Testing folder:",folder)
            priv_key = load_private_key(f"{TEST_DIRECTORY}{folder}/{PRIV_PEM}", PRIVPW)
            data, home_id, user_id = deconceal(priv_key, raw_suci_data, savefile=False)
            with self.subTest(home_id=home_id, user_id=user_id, expected_home_id=ENTITY_NAME_HOME, expected_user_id=ENTITY_NAME_USER):
                self.assertEqual(home_id, ENTITY_NAME_HOME)
                self.assertEqual(user_id, ENTITY_NAME_USER)
            print()
            print(f"{data}\n")
        if DELETE_FOLDER: rmtree(TEST_DIRECTORY)

         

if __name__ == '__main__':
	unittest.main()