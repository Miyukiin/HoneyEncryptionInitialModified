# Original Unmodified Source: https://github.com/torjusbr/bip39-honey-encryption
# Encrypt: python encrypt.py -e -s Resources/test_seed.txt -o Output/ciphertext.txt
# Decrypt: python encrypt.py -d -c Output/ciphertext.txt -o Output/plaintext.txt

import argparse
import base64
import json
from random import Random
import argon2
from getpass import getpass
from Crypto.Cipher import AES
from hashlib import sha256 # Probably used by implementer in a previous different interpretation of the algorithm.
from Crypto import Random
from Resources.wordlist import *

honeypasswords = [] # My Modification

# Simple HP Generation, My Modification for Demonstration Purposes Only.
def generateWriteHP(password): 
    honeypasswords.append("5" + password.upper())
    honeypasswords.append(password + "123")
    honeypasswords.append(password.lower() + "4")
    honeypasswords.append(password + password[-1])
    honeypasswords.append(password)
    
    with open("Output/HoneyPasswordList.txt", "w") as out_file:
        out_file.write(json.dumps(honeypasswords))
        
def readHP(password):
    with open("Output/HoneyPasswordList.txt", "r") as read_file:
        honeypasswords = json.load(read_file)
    if password in honeypasswords:
        return True
# Simple HP Generation, My Modification for Demonstration Purposes Only.       





def dte_encode(seed_file):
    plaintext = [] 
    with open(seed_file) as seed:
            for word in seed:
                word = word.replace("\n","")
                index = wordlist.index(word)
                byte_value = int_to_bytes(index, 16)
                plaintext.append(byte_value)
    return  b"".join(plaintext)

def dte_decode(text):
    words = []
    byte_numbers = [text[i:i+16] for i in range(0, len(text), 16)]
    for byte_number in byte_numbers:
        index = int_from_bytes(byte_number) % 2048
        words.append(wordlist[index]) 
    return words

def encrypt(dte, key):
    iv = Random.new().read(AES.block_size)
    obj = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = obj.encrypt(dte)
    
    return ciphertext, iv

def decrypt(ciphertext, key, iv):
    obj = AES.new(key, AES.MODE_CBC, iv)
    plaintext = obj.decrypt(ciphertext)
    
    return plaintext

def derive_key(password, salt=Random.new().read(16)):
    argon2id_hash = argon2.low_level.hash_secret_raw(password.encode("utf8"), salt, time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, type=argon2.low_level.Type.ID)
    return argon2id_hash, salt

def write_ciphertext(salt, ciphertext, iv, filename):
    with open(filename, "w") as out_file:
        out_file.write(json.dumps({"salt": base64.b64encode(salt).decode("utf8"), "iv": base64.b64encode(iv).decode("utf8"), "ciphertext": base64.b64encode(ciphertext).decode("utf8")}).encode("utf8").decode("utf8"))

def write_plaintext(plaintext, filename):
    with open(filename, "w") as out_file:
        for word in plaintext:
            out_file.write(word + "\n")

def read_ciphertext(filename):
    values = []
    with open(filename) as in_file:
        data = json.load(in_file)
        return base64.b64decode(data["salt"]), base64.b64decode(data["iv"]), base64.b64decode(data["ciphertext"])

def int_to_bytes(x: int, num_bytes) -> bytes:
    return x.to_bytes(num_bytes, "big")
    
def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, "big")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-s", dest="seed_file", type=str, help="BIP039 seed file")
    parser.add_argument("-c", dest="ciphertext_file", type=str, help="Encrypted BIP039 seed file")
    parser.add_argument("-o", dest="out_file", type=str, help="Output file")
    parser.add_argument("-d", action="store_true", default=False, help="Decrypt")
    parser.add_argument("-e", action="store_true", default=False, help="Encrypt")

    args = parser.parse_args()

    if args.d == args.e:
        print("Encrypt (-e) or decrypt (-d)")
    elif args.e:
        if args.seed_file == None or args.out_file == None:
            print("Missing mandatory encryption flags -s or -o.")
            exit()
        # password = getpass()
        # password2 = getpass()
        password = input("Password: ") # My Modification so that input is visible.
        password2 = input("Confirm Password: ") # My Modification so that input is visible.
        if password != password2:
            print("Passwords did not match")
        else:
            generateWriteHP(password) # My Modification, write and generate honey passwords with the real password inside.
            key, salt = derive_key(password)
            dte = dte_encode(args.seed_file)
            ciphertext, iv = encrypt(dte, key)
            write_ciphertext(salt, ciphertext, iv, args.out_file)
            print("Ciphertext written to", args.out_file)
            
    elif args.d:
        if args.ciphertext_file == None or args.out_file == None:
            print("Missing mandatory decryption flags -c or -o.")
            exit()
        # password = getpass()
        password = input("Password: ") # My Modification so that input is visible.
        if readHP(password): # My Modification. If it is a honey Password continue and print false text, or if Password print real text.
            salt, iv, ciphertext = read_ciphertext(args.ciphertext_file)
            key, salt = derive_key(password, salt)
            plaintext = decrypt(ciphertext, key, iv)
            dte = dte_decode(plaintext)
            write_plaintext(dte, args.out_file)
            print("Plaintext written to", args.out_file)
        else: # My Modification: Else print incorrect password because it isnt a honey password, and it isnt the password.
            print("Incorrect Password")

    """
    HEnc (K, M)  
        S ¬$ encode(M) 
        R ¬$ {0, 1}n  
        S‟ ¬ H (R, K)  
        C ¬ S‟⊕ S   
        return (R, C) 

    HDec (K, (R, C)) 
        S‟¬ H (R, K)   
        S ¬ C ⊕ S‟   
        M ¬ decode(S) 
        return M 
        
    Notes:
    1. In the original Honey Encryption algorithm described in your provided documentation, 
    there's no mention of AES (Advanced Encryption Standard) or any specific encryption mechanism. 
    Instead, it outlines the process in terms of generating random values, hashing, and performing XOR operations.
    2. In the original algorithm, H (R, K) refers simply, to the creation of S‟ through  password-based key derivation function as seen in Argon2 here.
    3. Basically, encode M to S and M ¬ decode(S) is a method. 
        Generate R, Nonce or synonymously R is another method. 
        H(R,K) to S" is another method. 
        Of which all these methods vary depending on the implementer.
        
        In our example, encode m to s is done through indexing
        r generation is done through random 16 bytes and used in AES
        So XOR is no longer needed, and thereby deriving S" is no longer needed too.
        So implementer just encrypts it using AES(R,K)
        decodes it using decrypt AES(R,K)
        and maps it to original word through indexing.
        All wrong passwords will be given fake password.
        
        Again, the given algorithm can be followed to the dot, like, not using AES and just deriving R,K to use it for xor. 
        
        The only thing that does not vary is the xor, although both operands have to be of the same byte length, so a padding method is likely used.
    
    So, kailangan nating maging careful na yung sop natin is hindi implementation nung algorithm, pero enhancement nya. Kasi nga ambiguous yung implementation nito.
    
    
    # Modified to include simple honey passwords generation for demonstration purposes.
    # May need own dte, separate storage for R and salt,  and own mappings and own honey password generation for proposed algorithm.
    
    Possible SOPS:
        1. Construct Good OPP DTE encoder, and storage space and method.
            1.1 Encoding method for Messages.
        2. Construct good honey password generation.
        
    Algorithm:
    This simulator slightly modifies the original algorithm (No XOR but uses AES), but the idea is the same.
    
    Using AES as symmetric encryption method. Other symmetric encryptions methods are Data Encryption Standard (DES), Triple Data Encryption Standard (3DES), and Blowfish.
    Using Argon2 to derive key from password by hashing it. (password-based key derivation function) Other PBKDFS are pbkdf2, scrypt
    
    According to this simulator:
        Encryption
            1. Get user password
            2. Confirm user password
            3. If password match continue, else do not continue,
            4. Derive key from user password
                4.1 Generate salt of 16 bytes using module random
                4.2 Generate hash (key) using Argon2 and various parameters
                4.3 Return hash of length 32, and salt of bytes 16.
                4.4 Hash of length 32 is our K
            5. Take message (in the form of the seed_file, which we provide as argument as text_seed.txt in the command), and dte encode it
                5.1 This is the step 'S ←$ encode(M)'
                5.2 In this simulator, the DTE encode step consists of 
                    5.2.1 For each word in seed file:
                        5.2.1.1 remove all newline characters
                        5.2.1.2 get the int index of the word inside the wordlist
                        5.2.1.3 convert the int index into 16 bytes form.
                        5.2.1.4 append this 16 bytes to the plaintext list. 
                        5.2.1.5 concatenate each byte string in the plaintext list to each other
                        5.2.1.6 So plaintext list is a list of 16 bytes form of the index of the words.
                        5.2.1.7 return plaintext list as our S.
            6. AES Encrypt using K and R
                6.1 This is the step 'S' <-H(R,K)'
                6.2 In this simulator, the encrypt step consists of 
                    6.2.1 Generate R or AES' IV using module Random.
                    6.2.2 Create a new AES Cypher utilizing AES MODE CBC to encrypt using key and iv
                        6.2.2.1 ECB mode: Electronic Code Book mode
                                CBC mode: Cipher Block Chaining mode
                                CFB mode: Cipher FeedBack mode
                                OFB mode: Output FeedBack mode
                                CTR mode: Counter mode
                    6.2.3 Encrypt S using Key and IV to produce ciphertext

        Decryption
            1. Get User Password
            2. Read salt, iv, ciphertext from database (ciphertext.txt as we provided in argument)
            3. Derive key from user password
                3.1 Use Salt read from database.
                3.2 Generate hash (key) using Argon2 and same various parameters to encrypt
                3.3 Return hash of length 32, and salt of bytes 16.
                3.4 Hash of length 32 is our K
            4. Decrypt ciphertext using IV from database and the K of provided password.
                4.1 Create a new AES Cypher utilizing AES MODE CBC to encrypt using key and iv
                4.2 Decrypt S using Key and IV
            6. Find M using S Decode
                6.1 This is the step 'M ¬ decode(S)'
                6.2 split the bytes into 16 byte chunks
                6.3 convert the int index from 16 bytes form.
                6.4 Find the corresponding word using the index in the wordlist.
    """