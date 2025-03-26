# Encrypt: python -m Original_HE.encryptOrig -e -s test_seedOrig.txt -o ciphertextOrig.txt -f "Original_HE"
# Decrypt: python -m Original_HE.encryptOrig -d -c ciphertextOrig.txt -o plaintextOrig.txt -f "Original_HE" 

# This simulator closely follows the algorithm.

import argparse
import argon2
import base64
import json
import time
import os
from Crypto import Random
from Original_HE.wordlistOrig import *
from utilities.HoneyPasswordGeneration import ExistingPasswordGeneration


def wait_print():
    time.sleep(2)
    print("-------------------------------------------------------------- ")
    print("\n\x1b[0m") # Reset Formatting
    
honeypasswords = []

def generateWriteHP(password, subfolder):
    print("\x1b[3m\x1b[33m\nGenerating honey passwords . . . . . .")
    # honeypasswords.append("5" + password.upper())
    # honeypasswords.append(password + "123")
    # honeypasswords.append(password.lower() + "4")
    # honeypasswords.append(password + password[-1])
    # honeypasswords.append(password)
    
    instance = ExistingPasswordGeneration(password)
    honeypasswords, sugarword_index = instance.choose_method(1)

    print(f"Honeypasswords for {password}: \n")

    for i in range(len(honeypasswords)):
        print(f"{honeypasswords[i]}: Index {i}")
    
    print(f"Sugarword Index: {sugarword_index}")
    wait_print()

    with open(os.path.join(subfolder, "HoneypasswordOrig.txt"), "w") as out_file:
        out_file.write(json.dumps(honeypasswords))

def readHP(password, subfolder):
    with open(os.path.join(subfolder, "HoneypasswordOrig.txt"), "r") as read_file:
        honeypasswords = json.load(read_file)
    return password in honeypasswords

def dte_encode(seed_file):
    plaintext = []
    with open(seed_file) as seed:
        print("\x1b[3m\x1b[33m\nMapping message to seed . . . . . .")
        print(f"Messages, seed, and byte values:\n")
        for word in seed:
            word = word.strip()
            index = wordlist.index(word) 
            byte_value = int_to_bytes(index, 2) 
            plaintext.append(byte_value)
            print('Word {} : Index {} : Byte Value: {}'.format(
                word.ljust(10), 
                str(index).ljust(10), 
                str(byte_value).ljust(10))
            )
        print(f"\nBinary String of Message: {b"".join(plaintext)}")
        wait_print()
    return b"".join(plaintext)

def dte_decode(text):
    words = []
    byte_numbers = [text[i:i+2] for i in range(0, len(text), 2)] # creates a list of byte pairs (chunks of 2 bytes) from text. Works as the max index (2048) cannot be longer than two bytes. 2 bytes can only accommodate up to 2^(16bits) or 65535
    for byte_number in byte_numbers:
        index = int_from_bytes(byte_number) % 2048
        words.append(wordlist[index])
        
    print("\x1b[3m\x1b[33m\nMapping seed to message . . . . . .")
    for word in words:
        print(f"→ {word}")
    wait_print()
    return words

def encrypt(dte, key):
    print("\x1b[3m\x1b[33m\nXOR Encrypting Message . . . . . .")
    print(f"\nSeed: {dte}\nKey: {key}")
    ciphertext = xor_bytes(dte, key) # Key (64 Argon) most of the times are longer than DTE in byte size. Doesn't break encryption, but extra bytes aren't used and are wasted.
    print(f"\nCiphertext: {ciphertext}")
    wait_print()
    return ciphertext

def decrypt(ciphertext, key):
    print("\x1b[3m\x1b[33m\nXOR Decrypting Message . . . . . .")
    print(f"\nCiphertext: {ciphertext}\nKey: {key}")
    dte = xor_bytes(ciphertext, key) 
    print(f"\nSeed: {dte}")
    wait_print()
    return dte

def derive_key(password:str, salt=None):
    password_bytes = password.encode("utf-8") # String to bytes
    
    # Generate a salt of the same length as password_bytes, else read 16 as minimum for Argon2 compliance
    if salt is None and len(password_bytes) >= 16:
        salt = Random.new().read(len(password_bytes))
    elif salt is None and len(password_bytes) < 16:
        salt = Random.new().read(16)
        
    argon2id_hash = argon2.low_level.hash_secret_raw(
        password_bytes,  # String to bytes
        salt, 
        time_cost=2, 
        memory_cost=102400, 
        parallelism=8, 
        hash_len=64, 
        type=argon2.low_level.Type.ID
    )
    print("\x1b[3m\x1b[33m\nDeriving Hashed Value from key and salt . . . . . .")
    print(f"\nSalt: {salt}\nPassword: {password_bytes}")
    print(f"\nHashed Value: {argon2id_hash}")
    wait_print()
    return argon2id_hash, salt

def write_ciphertext(salt, ciphertext, filename):
    print("\x1b[3m\x1b[33m\nReturn Ciphertext and Salt . . . . . .")
    print(f"\nSalt: {salt}\nCiphertext: {ciphertext}")
    wait_print()
    with open(filename, "w") as out_file:
        out_file.write(json.dumps({
            "salt": base64.b64encode(salt).decode("utf8"), # Bytes to String Conversion
            "ciphertext": base64.b64encode(ciphertext).decode("utf8")
        }))

def write_plaintext(plaintext, filename):
    with open(filename, "w") as out_file:
        for word in plaintext:
            out_file.write(word + "\n")

def read_ciphertext(filename):
    with open(filename) as in_file:
        data = json.load(in_file)
        return base64.b64decode(data["salt"]), base64.b64decode(data["ciphertext"])

def int_to_bytes(x: int, num_bytes) -> bytes:
    return x.to_bytes(num_bytes, "big")

def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, "big")

def xor_bytes(bytes1, bytes2):
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-s", dest="seed_file", type=str, help="BIP039 seed file")
    parser.add_argument("-c", dest="ciphertext_file", type=str, help="Encrypted BIP039 seed file")
    parser.add_argument("-o", dest="out_file", type=str, help="Output file")
    parser.add_argument("-d", action="store_true", default=False, help="Decrypt")
    parser.add_argument("-e", action="store_true", default=False, help="Encrypt")
    parser.add_argument("-f", dest="subfolder", type=str, default="subfolder", help="Subfolder for files")

    args = parser.parse_args()

    subfolder = args.subfolder

    if args.d == args.e:
        print("Encrypt (-e) or decrypt (-d)")
    elif args.e:
        if args.seed_file is None or args.out_file is None:
            print("Missing mandatory encryption flags -s or -o.")
            exit()
        password = input("Password: ")
        password2 = input("Confirm Password: ")
        if password != password2:
            print("Passwords did not match")
        else:
            generateWriteHP(password, subfolder)
            key, salt = derive_key(password)
            dte = dte_encode(os.path.join(subfolder, args.seed_file))
            ciphertext = encrypt(dte, key)
            write_ciphertext(salt, ciphertext, os.path.join(subfolder, args.out_file))
            print("Ciphertext written to", args.out_file)
    elif args.d:
        if args.ciphertext_file is None or args.out_file is None:
            print("Missing mandatory decryption flags -c or -o.")
            exit()
        password = input("Password: ")
        if readHP(password, subfolder):
            salt, ciphertext = read_ciphertext(os.path.join(subfolder, args.ciphertext_file))
            key, _ = derive_key(password, salt)
            dte = decrypt(ciphertext, key)
            plaintext= dte_decode(dte)
            write_plaintext(plaintext, os.path.join(subfolder, args.out_file))
            print("Plaintext written to", args.out_file)
        else:
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
    """
    