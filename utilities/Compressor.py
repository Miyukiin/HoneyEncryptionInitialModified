# python -m utilities.Compressor
import zlib
from Resources.wordlist import wordlist
import pickle
import sys

def compress_wordlist(wordlist):
    """Compresses the word list using zlib."""
    return zlib.compress(pickle.dumps(wordlist))

def decompress_wordlist(compressed_data):
    """Decompresses the word list using zlib."""
    return pickle.loads(zlib.decompress(compressed_data))

# Compress the word list
compressed_words = compress_wordlist(wordlist)
print(f"Original Size: {sys.getsizeof(pickle.dumps(wordlist))} bytes")
print(f"Compressed Size: {sys.getsizeof(compressed_words)} bytes")

# Decompress the word list
decompressed_words = decompress_wordlist(compressed_words)
print(f"Decompressed Words: {decompressed_words}")

# Verify that the decompressed list matches the original
assert decompressed_words == wordlist, "Decompressed word list does not match the original!"
