# python -m utilities.Compressor
import zlib
from Resources.wordlist import wordlist
import json
import sys
import pprint
import time

def wait_print():
    time.sleep(2)
    print("-------------------------------------------------------------- ")
    print("\n\x1b[0m") # Reset Formatting

class Compressor:
    def __init__(self, wordlist):
        self.text = wordlist

    def compress_wordlist(self):
        """Compresses the word list using zlib."""
        json_data = json.dumps(self.text)
        return zlib.compress(json_data.encode("utf-8"), 9)  
    
    def decompress_wordlist(self, compressed_data):
        """Decompresses the word list using zlib."""
        decompressed_data = zlib.decompress(compressed_data).decode("utf-8")
        return json.loads(decompressed_data) 

if __name__ == "__main__":  
    compressor = Compressor(wordlist)
    print("\x1b[3m\x1b[33m\nOriginal Size: {} bytes".format(sys.getsizeof(json.dumps(compressor.text))))
    pprint.pprint(f"Original Words: {compressor.text}", width=1000)
    wait_print()
    
    compressed_words = compressor.compress_wordlist()
    print("\x1b[3m\x1b[33m\nCompressed Size: {} bytes".format(sys.getsizeof(compressed_words)))
    pprint.pprint(f"Compressed Words: {compressed_words}", width=1000)
    wait_print()

    decompressed_words = compressor.decompress_wordlist(compressed_words)
    print("\x1b[3m\x1b[33m\nDecompressed Size: {} bytes".format(sys.getsizeof(json.dumps(decompressed_words))))
    pprint.pprint(f"Decompressed Words: {decompressed_words}", width=1000)
    wait_print()

    if decompressed_words != compressor.text:
        print("Decompressed word list does not match the original!")
        assert decompressed_words == compressor.text, "Decompressed word list does not match the original wordlist."
        
    print("\x1b[3m\x1b[33m\nDecompressed word list matches the original wordlist.")
    wait_print()
