# Original Unmodified Source: https://github.com/torjusbr/bip39-honey-encryption
# Encrypt: python encrypt.py -e -s Resources/test_seed.txt -o Output/ciphertext.txt
# Decrypt: python encrypt.py -d -c Output/ciphertext.txt -o Output/plaintext.txt

import argparse
import base64
import json
from random import Random
import argon2
from Crypto import Random
from Resources.wordlist import wordlist
import hashlib
import time
from utilities.RBMRSA import try_generating_keys, try_eea_mod, try_decryption_crt, try_bitstuffing, try_destuffing, try_binary_conversion
from utilities.HoneyPasswordGeneration import ExistingPasswordGeneration, MLHoneywordGenerator
import pprint

def wait_print():
    time.sleep(2)
    print("-------------------------------------------------------------- ")
    print("\n\x1b[0m") # Reset Formatting
    
# Honey Password Generation
honeypasswords = [] 

def generateWriteHP(password, salt): 
    
    print("\x1b[3m\x1b[33m\nGenerating honey passwords . . . . . .")
    #generator = MLHoneywordGenerator()
    #honeyword_list, sugarword_index = generator.generate_honeywords(password)
    ### Testing only, Consistent Honey Passwords. Sugarword is index 3 ###
    honeyword_list = ["Commander23!467840", "Computerman8887776", "Componline2231**#$", "ComputerScience242", "Comport0071977****"]
    sugarword_index = 3
    ### Test End ###
    honeypasswords:list[str] = honeyword_list
    honeypassword_hashes:list[str] = []
    
    print(f"Honeypasswords for {password}: \n")
    
    for i in range(len(honeypasswords)):
        print(f"{honeypasswords[i]}: Index {i}")
    
    print(f"Sugarword Index: {sugarword_index}")

    
    for password in honeypasswords:
        honeypassword_hash, _ = derive_key(password, salt)
        honeypassword_hash = base64.b64encode(honeypassword_hash).decode('utf-8') # Encode the Raw Hash binary data into ASCII-safe characters
        honeypassword_hashes.append(honeypassword_hash)
    print(f"\x1b[3m\x1b[33m\nHoneypasswords and Honeyhashes for {honeypasswords[sugarword_index]}: \n")
    for hash_pass_tuple in zip(honeypassword_hashes, honeypasswords):
        print("{} : {}".format(hash_pass_tuple[0].ljust(50), hash_pass_tuple[1].ljust(50)))
    
    wait_print()
    
    with open("Output/HoneyPasswordList.txt", "w") as out_file:
        out_file.write(json.dumps({
            "honeypasswords":honeypassword_hashes, 
            "sugarword_index": sugarword_index    
        }))
        
def readHP(password_hash, salt):
    with open("Output/HoneyPasswordList.txt", "r") as read_file:
        data = json.load(read_file)
        honeypasswords = data["honeypasswords"]
        sugarword_index = data["sugarword_index"]
        # print(f"Honeypasswords for {password}: {honeypasswords}")
        # print(f"Sugarword Index: {sugarword_index}")
    if password_hash in honeypasswords:
        return True
    return False 

# Honey DTE
def dte_encode(seed_file):
    plaintext = [] 
    with open(seed_file) as seed:                
        print("\x1b[3m\x1b[33m\nMapping message to seed . . . . . .")
        print(f"Messages, seed, and byte values:\n")
        for word in seed:
            word = word.strip()
            index = wordlist.index(word)
            chunk_size_bytes = 2 # Must be the same size in DTE encode. Note that 2^chunk_size_bytes must be able to accommodate the largest seed integer in the DTE.
            byte_value = int_to_bytes(index, chunk_size_bytes) 
            plaintext.append(byte_value)
            print('Word {} : Index {} : Byte Value: {}'.format(
                word.ljust(10), 
                str(index).ljust(10), 
                str(byte_value).ljust(10))
            )
        print(f"\nBinary String of Message: {b"".join(plaintext)}")
        wait_print()
                # # print(byte_value) # Show Bytes in hexadecimal form (\x) of Test Seed Word Indices Individually.
    # # print(b"".join(plaintext)) # Show Bytes in hexadecimal form (\x) of Test Seed Word Indices Combined.
    return  b"".join(plaintext)

def dte_decode(text):
    words = []
    chunk_size_bytes = 2 # Must be the same size in DTE encode. Note that 2^chunk_size_bytes must be able to accommodate the largest seed integer in the dte.
    byte_numbers = [text[i:i+chunk_size_bytes] for i in range(0, len(text), chunk_size_bytes)] # creates a list of byte strings (default chunks of 2 bytes) from text. Works as the max index of wordlist (2048) cannot be longer than two bytes. 2 bytes can only accommodate up to 2^(16bits) or 65535
    for byte_number in byte_numbers:
        index = int_from_bytes(byte_number) % 2048 # 2048 represents the max index of the BIP-39 wordlist. Not necessary, only used to prevent out of range errors, index < or > wordlist.length
        words.append(wordlist[index]) 
    return words

# Encrypt Message using RMBRSA - Debugged and Verified
def encrypt(dte:bytes):
    bit_input = 16  # Bit length of RBMRSA. Adjust this as per bit length conventions. (256,512,1024,2048 etc.). Affects ciphertext, d length etc. See ciphertext. file
    bits = try_generating_keys.compute_bit(bit_input) # We just floor divide the bits by 4 - among the four prime numbers

    #p, q, r, s = try_generating_keys.generating_keys(bits) # We produce 4 random-bit prime numbers with the divided bit length
    #N, PHI, e = try_generating_keys.computation_keys(p, q, r, s)
    ### Testing only, Consistent Values for consistent output ###
    p, q, r, s = 179, 139, 227, 137
    N, PHI, e = 773774219, 754999104, 53131
    ### Test End ###
    y, x = try_eea_mod.gcd_checker(e, PHI)
    d = try_eea_mod.generating_d(x, y, e, PHI) # We compute for the private key.
    
    print("\x1b[3m\x1b[33m\nOutputting RBMRSA parameters . . . . . .")
    print("Four Prime Numbers:\np = {}, q = {}, r = {}, s = {}".format(p,q,r,s))
    print("n = {}, totient N (PHI) = {}, e = {}".format(N, PHI, e))
    print("y = {}, x = {}".format(y,x))
    print("Public Key (e, N) = ({}, {})".format(e, N))
    print("Private key (d, N) = ({}, {})".format(d, N))
    wait_print()
    
    with open("Output/HoneyPasswordList.txt", "r") as read_file:
        data = json.load(read_file)
        honeypasswords:list[str] = data["honeypasswords"]
        sugarword_index:int = data["sugarword_index"]
        
    print("\x1b[3m\x1b[33m\nPrinting HoneyPasswords . . . . . .")
    for i in range(len(honeypasswords)):
        print(f"{honeypasswords[i]}: Index {i}")
    print(f"Sugarword Index: {sugarword_index}")
    wait_print()
        
    fake_passwords = honeypasswords.copy() # Make another copy, not a reference.
    fake_passwords.pop(sugarword_index) # Remove sugarword from list of honeypasswords.
    
    honey_keys: list[dict[str, int]] = [{} for _ in range(len(honeypasswords))]  # Ensures the list is pre-filled with empty dictionaries of length honeypasswords.
    # Attach a fake private key to every honey password.
    j=0
    print("\x1b[3m\x1b[33m\nPrinting Fake Private Key . . . . . .")
    for i in range (len(honeypasswords)):
        if i != sugarword_index:
            honey_keys[i] = {fake_passwords[j]: derive_fake_private_key(fake_passwords[j], d.bit_length(), PHI)}
            j = j + 1
            continue           
        honey_keys[i] = {honeypasswords[sugarword_index]: d} # Insert sugarword with actual d private key inside honey_keys list of dictionaries.
    wait_print()
    
    print("\x1b[3m\x1b[33m\nPrinting HoneyPasswords with Private Keys . . . . . .")
    for hp_pkey_pair in honey_keys:
        hp, pkey = next(iter(hp_pkey_pair.items()))
        print("{}: {}".format(hp.ljust(25), str(pkey).ljust(25)))
    print(f"Sugarword Index: {sugarword_index}")
    wait_print()

    print("\x1b[3m\x1b[33m\nSeed Encryption . . . . . .")
    
    dte_bytes:list[int] = list(dte)  # Convert the byte sequence into a list of int.
    encrypted_bytes:list[int] = [pow(byte, e, N) for byte in dte_bytes]  # Encrypt each element of the list and store it in another list.
    print("Seed Byte String: ", dte)
    print("Array of Integers: ", dte_bytes) 
    print("Array of Encrypted Integers: ", encrypted_bytes) 
    
    # Bitstuffing 
    binary_list = try_binary_conversion.decimal_to_binary(encrypted_bytes) # Convert integers in the list into binary for bitstuffing process.
    print(f"Binary Array of Encrypted Integers: {binary_list}")
    wait_print()

    ################## Debugging ##################
    save_binary_list_initial = binary_list.copy()
    ################## Debugging ##################
    
    # print("Before Bitstuffing: ", binary_list[:20])
    bitX = try_bitstuffing.bitstuffX(binary_list)
    bitY = try_bitstuffing.bitstuffY(bitX)
    bitZ = try_bitstuffing.bitstuffZ(bitY)
    
    print("\x1b[3m\x1b[33m\nBit Stuffing . . . . . .")
    print("bitX: {}".format(str(bitX).ljust(30)))
    print("bitY: {}".format(str(bitY).ljust(30)))
    print("bitZ: {}".format(str(bitZ).ljust(30)))
    
    # Convert back each stuffed binary bits element in the list, into list of int.
    binary_list:list[int] = [try_binary_conversion.binary_to_decimal(element) for element in bitZ]
    
    print(f"Bit-stuffed Array of Encrypted Integers: {binary_list}")
    wait_print()
    
    ################## Debugging ##################
    desZ = try_destuffing.destuffZ(bitZ)
    desY = try_destuffing.destuffY(desZ)
    desX = try_destuffing.destuffX(desY)
    # print("Is desX == Initial Binary List before BitStuffing?: ", desX == save_binary_list_initial)
    # print("desX: ",desX[:20])
    ################## Debugging ##################
    
    print("\x1b[3m\x1b[33m\nConversion to Single Byte String . . . . . .")
    # Convert all int elements in the list back into a single byte sequence.
    max_bits = max(c.bit_length() for c in binary_list)  # Get largest bit size in `binary_list`
    byte_list:list[bytes] = [c.to_bytes((max_bits + 7) // 8, "big") for c in binary_list]  # Ensures all numbers fit into a fixed byte size
    
    ciphertext: bytes = b''.join(byte_list)
    
    print("Bit-stuffed Binary Array of Encrypted Integers: ", byte_list)
    print("Chunk Size: ", max_bits)
    print("Ciphertext Byte String: ", ciphertext)

    
    rmbrsa_parameters:dict = {"N": N, "e": e, "d": d, "p": p, "q": q, "r": r, "s": s, "PHI": PHI, "honey_keys": honey_keys, "chunk_size": max_bits}
    
    return ciphertext, rmbrsa_parameters

# Decrypt Message using RMBRSA - Debugged and Verified
def decrypt(ciphertext: bytes, rbmrsa_parameters: dict, password_hash:str):
    
    N:int = rbmrsa_parameters["N"]
    p:int = rbmrsa_parameters["p"]
    q:int = rbmrsa_parameters["q"]
    r:int = rbmrsa_parameters["r"]
    s:int = rbmrsa_parameters["s"]
    honey_keys: dict[str, int] = {k: v for element in rbmrsa_parameters["honey_keys"] for k, v in element.items()} 
    # For reference: [{"pass123":fake d},{"pass456":fake d}] -> {"pass123":fake d, "pass456":fake d}
    
    # Retrieve honey_key using input password.
    d:int = honey_keys[password_hash]
    
    # Compute Modular Inverses for CRT Optimization
    pInv, qInv, rInv, sInv = try_decryption_crt.modInv_Computation(N, p, q, r, s)
    dp, dq, dr, ds = try_decryption_crt.crt_equations(p, q, r, s, N, d)
    
    print("\x1b[3m\x1b[33m\nPrinting Decryption Modular Inverses . . . . . .")
    print(f"pInv:{pInv}\nqInv:{qInv}\nrInv:{rInv}\nsInv:{sInv}")
    print(f"dp:{dp}\ndq:{dq}\ndr:{dr}\nds:{ds}")
    
    # We convert the single byte sequence into a list of bytes.
    chunk_size = rbmrsa_parameters['chunk_size'] 
    print("Chunk Size: ", chunk_size)
    wait_print()

    byte_list = []
    i = 0
    while i < len(ciphertext):
        encrypted_int = int.from_bytes(ciphertext[i:i+((chunk_size + 7) // 8)], "big")
        byte_list.append(encrypted_int)
        i += ((chunk_size + 7) // 8) # Use stored chunk size and do the same formula.
        
    print("\x1b[3m\x1b[33m\nPrinting Bit-stuffed Array of Encrypted Integers and Bit-stuffed Binary List of Encrypted Integers . . . . . .")
    print(f"Bit-stuffed Array of Encrypted Integers: {byte_list}")
    binary_list = try_binary_conversion.decimal_to_binary(byte_list)
    print(f"Bit-stuffed Binary Array of Encrypted Integers: {binary_list}")
    wait_print()

    # Bit destuffing 
    # print("Decrypted Integers Binary List: ", binary_list[:20])
    desZ = try_destuffing.destuffZ(binary_list)
    desY = try_destuffing.destuffY(desZ)
    desX = try_destuffing.destuffX(desY)
    # print("After Destuffing: ", desX[:20])
    
    print("\x1b[3m\x1b[33m\nDeStuffing of Bit-stuffed Binary Array of Encrypted Integers . . . . . .")
    print("desZ: {}".format(str(desZ).ljust(30)))
    print("desY: {}".format(str(desY).ljust(30)))
    print("desX: {}".format(str(desX).ljust(30)))
    wait_print()
    
    print("\x1b[3m\x1b[33m\nDe-stuffed Binary Array of Encrypted Integers to Integer Conversion . . . . . .")
    # Convert back each stuffed binary bits element in the list into list of int.
    binary_list:list[int] = [try_binary_conversion.binary_to_decimal(element) for element in desX]
    print("Array of Encrypted Integers: ", binary_list)

    # Decrypt each integer in the list.
    decrypted_integers:list[int] = try_decryption_crt.four_parts(
        binary_list, p, q, r, s, N, pInv, qInv, rInv, sInv, dp, dq, dr, ds
    )
    print("Array of Decrypted Integers: ", decrypted_integers)

    # Converts the list of integers back to a single byte sequence.
    dte = bytes(c % 256 for c in decrypted_integers)  # Ensure values fit in the valid byte range of 0-255, because a d_fake may produce result in decrypted_integers that are outside this range.
    print(f"Seed Byte String: {dte}")
    wait_print()
    return dte

def derive_key(password:str, salt=None):
    password_bytes = password.encode("utf-8") # String to bytes
    if salt is None:
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

def derive_fake_private_key(password: str, d_bit_length: int, PHI: int):
    """Derives a fake private key with the same bit length as the real private key `d`."""
    hashed = hashlib.sha256(password.encode()).hexdigest()  # Hash password to hex string
    fake_key_int = int(hashed, 16)  # Convert hexa hash to integer
    
    # Keeps d_fake within valid range of modular arithmetic, not negative or too large.
    d_fake = fake_key_int % PHI  
    
    # Force `d_fake` to have exactly the same bit length as `d`
    bit_mask = 1 << (d_bit_length - 1) # 100...000 (2048 bits long)
    d_fake |= bit_mask  # Sets the highest bit of d_fake to 1 so it is the same length
    
    print(f"Honey Password: {password}")
    print(f"Password Encoded: {password.encode()}")
    print(f"Password Hashed: {hashlib.sha256(password.encode())}")
    print(f"Password Hexa: {hashed}")
    print(f"\nFake Key Integer: {fake_key_int}")
    print(f"Fake d: {fake_key_int % PHI  }")
    
    print(f"D bit length: {d_bit_length}")
    print(f"Bit Mask: {bit_mask}")
    print(f"Final fake d: {d_fake}\n")
    
    return d_fake

def write_ciphertext(salt, ciphertext, rbmrsa_parameters:dict, filename):
    with open(filename, "w") as out_file:
        # Decodes the hexadecimal form bytes (\xNN) into Base64 String and then to corresponding UTF-8 string. Then write the json to the file.
        data = {
            "salt": base64.b64encode(salt).decode("utf8"),
            "ciphertext": base64.b64encode(ciphertext).decode("utf8")
        }
        
        # We dynamically store the value of rmbrsa_parameters dictionary.
        for key, value in rbmrsa_parameters.items():
            data[key] = value  

        out_file.write(json.dumps(data, indent=4))

def write_plaintext(plaintext, filename):
    with open(filename, "w") as out_file:
        for word in plaintext:
            out_file.write(word + "\n")

def read_ciphertext(filename):
    with open(filename) as in_file:
        data = json.load(in_file)    
        rbmrsa_parameters:list = {
            "N": data["N"], 
            "e": data["e"], 
            "d": data["d"], 
            "p": data["p"], 
            "q": data["q"], 
            "r": data["r"], 
            "s": data["s"], 
            "PHI": data["PHI"], 
            "honey_keys": data["honey_keys"], 
            "chunk_size": data['chunk_size']
        }
        return base64.b64decode(data["salt"]), rbmrsa_parameters, base64.b64decode(data["ciphertext"])

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
        password = input("Password: ") 
        password2 = input("Confirm Password: ")
        if password != password2:
            print("Passwords did not match")
        else:
            _, salt = derive_key("password")
            generateWriteHP(password, salt) # Write and generate honey passwords with the real password inside.
            dte = dte_encode(args.seed_file)
            ciphertext, rbmrsa_parameters = encrypt(dte)
            write_ciphertext(salt, ciphertext, rbmrsa_parameters, args.out_file)
            print("Ciphertext written to", args.out_file)
            
    elif args.d:
        if args.ciphertext_file == None or args.out_file == None:
            print("Missing mandatory decryption flags -c or -o.")
            exit()
        password = input("Password: ") 
        salt, rbmrsa_parameters, ciphertext = read_ciphertext(args.ciphertext_file)
        key, _ = derive_key(password, salt)
        key = base64.b64encode(key).decode('utf-8') # Encode the Raw Hash binary data into ASCII-safe characters
        if readHP(key, salt): # If it is a honey Password continue and # print false text, or if Password # print real text.
            dte = decrypt(ciphertext, rbmrsa_parameters, key)
            plaintext = dte_decode(dte)
            write_plaintext(plaintext, args.out_file)
            print("Plaintext written to", args.out_file)
        else: # Else print incorrect password because it isnt a honey password, and it isnt the password.
            print("Incorrect Password")

    """
    Original Algorithm:
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
    
    Proposed Algorithm:
    
        
    Outdated Notes as of 16/02/2025:
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
                6.4 Find the corresponding word using the index in the wordlist._
    """