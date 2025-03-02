# python -m utilities.Compressor
import zlib
from Resources.wordlist import wordlist
import pickle
import sys

class Compressor:
    def __init__(self, wordlist):
        self.text = wordlist

    def compress_wordlist(self):
        """Compresses the word list using zlib."""
        return zlib.compress(pickle.dumps(self.text), 9)

    def decompress_wordlist(self, compressed_data):
        """Decompresses the word list using zlib."""
        return pickle.loads(zlib.decompress(compressed_data))

if __name__ == "__main__":  
    compressor = Compressor(wordlist)
    compressed_words = compressor.compress_wordlist()
    print(f"Original Size: {sys.getsizeof(pickle.dumps(wordlist))} bytes")
    print(f"Compressed Size: {sys.getsizeof(compressed_words)} bytes")

    # Decompress the word list
    decompressed_words = compressor.decompress_wordlist(compressed_words)
    print(f"Decompressed Words: {decompressed_words}")

    # Verify that the decompressed list matches the original
    assert decompressed_words == wordlist, "Decompressed word list does not match the original!"
