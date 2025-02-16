# based on: https://repl.it/@billbuchanan/getprimen
# based on: https://repl.it/@billbuchanan/getprimen
import time
from try_bitstuffing import bitstuffX, bitstuffY, bitstuffZ
from try_destuffing import destuffZ, destuffY, destuffX
from try_format_bitstuff import format_bitstuffing
from try_format_destuff import format_destuff
from try_generating_keys import generating_keys, computation_keys, compute_bit
from try_binary_conversion import decimal_to_binary, binary_to_decimal
from try_eea_mod import gcd_checker, generating_d
from try_decryption_crt import crt_equations, modInv_Computation, four_parts


def wait_print():
    time.sleep(2)
    print(".  .  .  .  .  .  .  .  .  .  .  .  . ")
    time.sleep(1)
    print(".  . ")
    time.sleep(1)
    print("\n\x1b[0m")


# Get bit-length from user input
bit_input = int(input("\n\x1b[32m\x1b[1mEnter your bit-length:\x1b[30m "))
print("\n\x1b[0m")

time.sleep(1)
print("\x1b[3m\x1b[33mGenerating and computing for keys . . . . . .")
wait_print()

gen_time_st = time.time()

# Divides bit-length into 4 for the 4 prime numbers and get the whole number
bits = compute_bit(bit_input)

# Produces 4 random-bit prime number
print(
    "============================================================================================================================================="
)
print("No of bits in prime is ", bits)

p, q, r, s = generating_keys(bits)
print("\n\x1b[36m\x1b[1mGenerated Random Prime keys: \x1b[0m")
print("Random n-bit Prime (p): ", p)
print("Random n-bit Prime (q): ", q)
print("Random n-bit Prime (r): ", r)
print("Random n-bit Prime (s): ", s)
print(
    "============================================================================================================================================="
)

N, PHI, e = computation_keys(p, q, r, s)

# Computes the whole bit-length (N)
print("\n\x1b[36m\x1b[1mN = p*q*r*s =\x1b[0m", N)

# Computes for the Totient of N
print("\n\x1b[36m\x1b[1mPHI = (p-1)(q-1)(r-1)(s-1) =\x1b[0m", PHI)

# Public key (e)
print("\n\x1b[36m\x1b[1me =\x1b[0m", e)

y, x = gcd_checker(e, PHI)
d = generating_d(x, y, e, PHI)

gen_time_end = time.time()
gen_time = gen_time_end - gen_time_st
# Computes for the Private/Secret Key (d)
print("\x1b[36m\x1b[1md =\x1b[0m", d)

# Get message input from user
print("\n")
plain_text = input("\x1b[32m \x1b[1m Write msg:\x1b[30m ")

# print([ord(c) for c in plain_text]) #Converts string into uni code
print("\n\x1b[0m")

# timer
enc_st = time.time()

# Encryption of text message
print("\n\x1b[1mRSA Message: \x1b[0m", plain_text)
CipherText = [pow(ord(c), e, N) for c in plain_text]
print("\x1b[1m\x1b[31mRSA Cipher (c = M^e mod N): \x1b[0m", CipherText)

# Conversion of Decimal to Binary
print(
    "\n---------------------------------------------------------------------------------------------------------------------------"
)
BinaryText = decimal_to_binary(CipherText)
print("\x1b[36m\x1b[1mBinary Text:\x1b[0m", BinaryText)
print("\n")

# BitStuffing
bitX = bitstuffX(BinaryText)
bitY = bitstuffY(bitX)
bitZ = bitstuffZ(bitY)

print("====== bit stuffing ======")
print("\n\x1b[36m\x1b[1mbit X:\x1b[0m", bitX)
print("\n\x1b[36m\x1b[1mbit Y:\x1b[0m", bitY)
print("\n\x1b[36m\x1b[1mbit Z:\x1b[0m", bitZ)

BinaryText = bitZ

# Elapsed time for Encryption
enc_et = time.time()
enc_elapsedTime = enc_et - enc_st

# Formatting Presentation for sending
final_encoded_messages = format_bitstuffing(BinaryText)
print("\n\x1b[36m\x1b[1mEncoded Messages: \x1b[0m", final_encoded_messages)

# --- end of encryption process

# Send message to the internet
print("\n\x1b[3m\x1b[33mSending encrypted message to the internet . . . . ")
wait_print()

# --- start of decryption process

# Removing Format Presentation
decoded_message = format_destuff(final_encoded_messages)

dec_st = time.time()
# DeStuffing
print(
    "---------------------------------------------------------------------------------------------------------------------------"
)
# DeStuffing
desZ = destuffZ(decoded_message)
desY = destuffY(desZ)
desX = destuffX(desY)

print("====== de stuffing ======")
print("\n\x1b[36m\x1b[1mDestuff bit Z :\x1b[0m", desZ)
print("\n\x1b[36m\x1b[1mDestuff bit Y :\x1b[0m", desY)
print("\n\x1b[36m\x1b[1mDestuff bit X :\x1b[0m", desX)

BinaryText = desX

# Convertion of Binary to Decimal
CipherText = []
for binary in BinaryText:
    CipherText.append(binary_to_decimal(binary))

print("\x1b[36m\x1b[1m\nBinary Decrypted CipherText:\x1b[0m", CipherText)


# Decryption process
pInv, qInv, rInv, sInv = modInv_Computation(N, p, q, r, s)
dp, dq, dr, ds = crt_equations(p, q, r, s, N, d)
Decryption = four_parts(
    CipherText, p, q, r, s, N, pInv, qInv, rInv, sInv, dp, dq, dr, ds
)
print("\x1b[36m\x1b[1m\nRSA Decipher (c^d mod N):\x1b[0m", Decryption)
DT = [chr(c) for c in Decryption]
DecryptedText = "".join(DT)
dec_et = time.time()
dec_elapsedTime = dec_et - dec_st

print("\n\x1b[3m\x1b[33mPrinting Results . . . . ")
wait_print()

# Output
print(
    "\x1b[32m\x1b[1mResult: ==============================================================\x1b[0m"
)
print("\nKey Length: ", bit_input)
print("Version: TRY's Version")
print("\nGenerating Key Elapsed Time:", (gen_time * 1000), "milliseconds")
print("Encryption Elapsed Time:", (enc_elapsedTime * 1000), "milliseconds")
print("Decryption Elapsed Time:", (dec_elapsedTime * 1000), "milliseconds")
print("\x1b[32m\n\nDecrypted Message:\x1b[1m " + DecryptedText, "\x1b[0m")
print("\n\n")
