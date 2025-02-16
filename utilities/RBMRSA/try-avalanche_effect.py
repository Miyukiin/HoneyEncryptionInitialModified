# Added relative importing syntax (.), as it is now a package.
from .try_bitstuffing import bitstuffX, bitstuffY, bitstuffZ
from .try_destuffing import destuffZ, destuffY, destuffX
from .try_format_bitstuff import format_bitstuffing
from .try_format_destuff import format_destuff
from .try_generating_keys import generating_keys, computation_keys, compute_bit
from .try_binary_conversion import decimal_to_binary, binary_to_decimal
from .try_eea_mod import gcd_checker, generating_d
from .try_decryption_crt import crt_equations, modInv_Computation, four_parts

print("\n ----------")
print("MODIFIED RBMRSA Avalanche Checker Version:")
print("\n Key bit-length: 2048")
original_plaintext = input("\tEnter a phrase/text: ")
modified_plaintext = input("\tChange 1 part of the text/phrase: ")

# Algorithm keys -------
bit_input = 2048
bits = compute_bit(bit_input)

p, q, r, s = generating_keys(bits)

N, PHI, e = computation_keys(p, q, r, s)

y, x = gcd_checker(e, PHI)
d = generating_d(x, y, e, PHI)

# Encryption of text message
original_ciphertext = [pow(ord(c), e, N) for c in original_plaintext]

# Conversion of Decimal to Binary
Original_BinaryText = decimal_to_binary(original_ciphertext)

# BitStuffing
bitX = bitstuffX(Original_BinaryText)
bitY = bitstuffY(bitX)
bitZ = bitstuffZ(bitY)

Original_BinaryText = bitZ

# Modified text -----------------------------------------
# Algorithm keys -------
bits = compute_bit(bit_input)

p, q, r, s = generating_keys(bits)

N, PHI, e = computation_keys(p, q, r, s)

y, x = gcd_checker(e, PHI)
d = generating_d(x, y, e, PHI)

# Encryption of text message
modified_ciphertext = [pow(ord(c), e, N) for c in modified_plaintext]

# Conversion of Decimal to Binary
Modified_BinaryText = decimal_to_binary(modified_ciphertext)

# BitStuffing
bitX = bitstuffX(Modified_BinaryText)
bitY = bitstuffY(bitX)
bitZ = bitstuffZ(bitY)

Modified_BinaryText = bitZ


# Calculating Avalanche Effect (Bitwise XOR)
def compute_avalanche_effect(Original_BinaryText, Modified_BinaryText):
    total_bits = 0
    changed_bits = 0   

    # Iterate through each pair of original and modified ciphertexts
    for original, modified in zip(Original_BinaryText, Modified_BinaryText):
        # Convert ciphertexts to binary strings
        original_int = int(original, 2)
        modified_int = int(modified, 2)

        # Count the total number of bits
        total_bits += len(original)

        # Count the number of changed bits
        changed_bits += bin(original_int ^ modified_int).count("1")

    # Calculate the percentage of changed bits
    avalanche_percentage = (changed_bits / total_bits) * 100
    return avalanche_percentage, changed_bits, total_bits


avalanche_percentage, changed_bits, total_bits = compute_avalanche_effect(
    Original_BinaryText, Modified_BinaryText
)
print("\nchanged bits:", changed_bits)
print("total bits:", total_bits)

print("\nAvalanche Effect: {:.2f}%".format(avalanche_percentage))
print("---- end ----\n")
