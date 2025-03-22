# python -m utilities.Compressor
# Use LZW -> Huffman Coding -> Bytes to Address Storage Overhead.
from Resources.wordlist import wordlist
from collections import Counter
import heapq
import sys
import pprint
import math
import bitarray
import time
import itertools

def wait_print():
    time.sleep(2)
    print("-------------------------------------------------------------- ")
    print("\n\x1b[0m") # Reset Formatting

class Compressor():
    def __init__(self):
        self.huffman_reverse_codebook = None
        
    ### lzw METHODS ###
    def lzw_encode(self, text_to_encode:str):
        # Reference Section 5.2 Page 34 of Introduction to Data Compression by Blelloch Guy E.
        
        # Initialize dictionary with single character strings
        print("\x1b[3m\x1b[33m\nLZW compressing text . . . . . .")
        print(f"Text: {text}")
        dictionary = {chr(i): i for i in range(256)}
        print(f"Initial Dictionary: {dictionary}\n")
        # Start of the Next Code. Immediately after 0-255 ASCII Codes.
        next_code = 256  
        
        w = ""
        lzw_compressed_data:list = []

        # Every unique pattern, add to the dictionary.
        for c in text_to_encode:
            wc = w + c
            if wc in dictionary:
                w = wc
            else:
                lzw_compressed_data.append(dictionary[w])
                dictionary[wc] = next_code
                next_code += 1
                w = c
        if w:
            lzw_compressed_data.append(dictionary[w])

        print(f"Final Dictionary: {dictionary}\n")
        print(f"Output: {lzw_compressed_data}")
        wait_print()
        return lzw_compressed_data # Returns a List of Integers where instead of characters, they are represented by the integer unique pattern as specified in the dictionary.

    def lzw_decode(self, compressed_lzw_data:list[int]):
            
        # Initialize dictionary with single character strings
        dictionary = {i: chr(i) for i in range(256)}
        # Start of the Next Code. Immediately after 0-255 ASCII Codes.
        next_code = 256 
        w = chr(compressed_lzw_data.pop(0))
        decompressed_data = w

        for code in compressed_lzw_data:
            if code in dictionary:
                entry = dictionary[code]
            elif code == next_code:
                entry = w + w[0]  # Special case for newly formed entries
            else:
                raise ValueError("Decompression error: Invalid LZW code")

            decompressed_data += entry
            dictionary[next_code] = w + entry[0]
            next_code += 1
            w = entry
        
        #print(dictionary) # Debugging
        
        return decompressed_data
    
    ### HUFFMAN METHODS ###
    class HuffmanNode:
        counter = itertools.count()  # global class-level counter so that heap remains consistent; when frequencies are the same, they are not arbitrarily chosen when rebuilt.
        def __init__(self, symbol, freq):
            self.symbol = symbol
            self.freq = freq
            self.left = None
            self.right = None
            self.order = next(Compressor.HuffmanNode.counter)  # unique tiebreaker to becom deterministic when rebuilding tree during iteration process

        def __lt__(self, other):
            if self.freq == other.freq:
                return self.order < other.order  # break ties by insertion order (deterministic), because comparison by Int and None will yield error.
            return self.freq < other.freq
        
        def __repr__(self):
            return f"({self.symbol}:{self.freq})"
        
        def print_tree(self, node, indent="", branch="Root"):
            if node is not None:
                self.print_tree(node.right, indent + "     ", branch="R──")
                if node.symbol is not None:
                    print(f"{indent}{branch} ('{chr(node.symbol)}'/{node.symbol}:{node.freq})")
                else:
                    print(f"{indent}{branch} (None:{node.freq})")
                self.print_tree(node.left, indent + "     ", branch="L──")
            
    def build_frequency_table(self, data:list[int]):
        print("\x1b[3m\x1b[33m\nConstructing Frequency Table . . . . . .")
        frequency_table = Counter(data) 
        print(f"\nFrequency Table: {frequency_table}")
        wait_print()
        return frequency_table
    
    def build_huffman_tree(self, freq_table:dict):
        # Initialize
        print("\x1b[3m\x1b[33m\nConstructing Heap . . . . . .")
        heap = [self.HuffmanNode(symbol, freq) for symbol, freq in freq_table.items()]
        print(f"\nInitial Heap: {heap}")
        heapq.heapify(heap)
        print(f"\nHeapified Heap: {heap}")

        # Iterate
        while len(heap) > 1:
            print(f"\n\nLength of Heap: {len(heap)}")
            left = heapq.heappop(heap)
            right = heapq.heappop(heap)
            print(f"Left Node: {left}, Right Node: {right}")
            merged = self.HuffmanNode(None, left.freq + right.freq)
            print(f"Merged: {merged}")
            merged.left = left
            merged.right = right
            print(f"Merged Left Node: {merged.left}, Merged Right Node: {merged.right}")
            heapq.heappush(heap, merged)
            print(f"New Heap: {heap}")
            
        # Terminate
        print(f"\nHuffman Root Node: {heap[0]}")
        print("\nHuffman Tree Structure:")
        heap[0].print_tree(heap[0])
        wait_print()
        return heap[0]

    def build_huffman_codes(self, node:HuffmanNode, prefix="", codebook=None, reverse_codebook=None):
        """Generate Huffman codes and store both forward and reverse mappings."""
        if codebook is None:
            codebook = {}
        if reverse_codebook is None:
            reverse_codebook = {}

        if node:
            if node.symbol is not None:  # Leaf node
                codebook[node.symbol] = prefix
                reverse_codebook[prefix] = node.symbol  # Store for decoding
            self.build_huffman_codes(node.left, prefix + "0", codebook, reverse_codebook)
            self.build_huffman_codes(node.right, prefix + "1", codebook, reverse_codebook)

        return codebook, reverse_codebook
    
    def huffman_encode(self, lzw_compressed_data:list[int], codebook:dict):
        self.huffman_encoded_data = "".join(codebook[symbol] for symbol in lzw_compressed_data)
        return self.huffman_encoded_data # Returns a string containing binary numbers.
    
    def huffman_decode(self, huffman_encoded_data, reverse_codebook):
        """Decode Huffman-encoded bitstring using the reverse codebook."""
        current_code = ""
        decoded_output = []

        for bit in huffman_encoded_data:
            current_code += bit
            if current_code in reverse_codebook:  # Check if a valid symbol
                decoded_output.append(reverse_codebook[current_code])
                current_code = ""  # Reset for next symbol

        return decoded_output  # Returns list of LZW codes

    
    ### Binary Conversion Methods ###
    def huffman_to_bytes(self, binary_string:str):
        # Ensure the length is a multiple of 8 by padding
        padding_length = (8 - len(binary_string) % 8) % 8
        padded_binary = binary_string + "0" * padding_length

        # Store padding length in the first byte for decoding
        padding_info = "{:08b}".format(padding_length)  # 8-bit representation of padding length
        padded_binary = padding_info + padded_binary  # Store padding at the start

        # Convert binary string to bytearray
        byte_array = bytearray()
        for i in range(0, len(padded_binary), 8):
            byte_array.append(int(padded_binary[i:i+8], 2))

        return bytes(byte_array)
    
    def bytes_to_huffman(self, byte_data):
        # Extract padding info from the first byte
        padding_length = byte_data[0]  # First byte stores padding length
        
        # Convert the remaining bytes to binary string
        binary_string = "".join(f"{byte:08b}" for byte in byte_data[1:])  # Skip padding byte

        # Remove padding
        return binary_string[:-padding_length] if padding_length > 0 else binary_string
    
    def lzw_to_bitstream(self, lzw_compressed_data):
        "Converts LZW Output into bytes form for accurate measurement of LZW output byte size."
        max_code = max(lzw_compressed_data)  # Get the highest dictionary code used
        bits_per_code = max(9, math.ceil(math.log2(max_code + 1)))  # Adjust bit size dynamically (min 9 bits) 256, 512, 1024, 2048, 4096 where 2^n where n is bits required to store the max code.

        bit_data = bitarray.bitarray()
        encoded_bits = ''.join(format(code, f'0{bits_per_code}b') for code in lzw_compressed_data)  # Pack each number

        #print(f"Bits Per LZW Code: {bits_per_code}")
        bit_data.extend(encoded_bits)  # Store as bitstream
        return bit_data.tobytes()
    
    def compress(self, text:str):
        # LZW Compress the string of text
        lzw_compressed_data = self.lzw_encode(text)
        
        # Build Huffman Frequency Table
        freq_table = self.build_frequency_table(lzw_compressed_data)
        
        # Build Huffman Tree
        huffman_tree = self.build_huffman_tree(freq_table)
        huffman_codebook, huffman_reverse_codebook = self.build_huffman_codes(huffman_tree)
        
        self.huffman_reverse_codebook = huffman_reverse_codebook

        # Huffman Encode the LZW Output
        huffman_compressed_data = self.huffman_encode(lzw_compressed_data, huffman_codebook)
        
        # Binary Encode the Huffman Output
        binary_compressed_data = self.huffman_to_bytes(huffman_compressed_data)
        
        return binary_compressed_data, huffman_reverse_codebook
    
    def decompress(self, binary_compressed_data, huffman_reverse_codebook = None):
        
        # Convert Binary Input into Huffman Output
        huffman_compressed_data = self.bytes_to_huffman(binary_compressed_data)
        
        # Convert Huffman Input into LZW Output.
        if huffman_reverse_codebook:
            lzw_compressed_data = self.huffman_decode(huffman_compressed_data, huffman_reverse_codebook) # If stored huffman is available, different encoding and decoding session.
        else:
            lzw_compressed_data = self.huffman_decode(huffman_compressed_data, self.huffman_reverse_codebook) # If encoding and decoding is same session
        
        # Decode LZW Input into String
        decompressed_data = self.lzw_decode(lzw_compressed_data)
        
        # Construct List, using whitespace as separator.
        decompressed_data = decompressed_data.split()
        
        return decompressed_data
    


  
if __name__ == "__main__":
    ### TESTING PURPOSES ###
    instance = Compressor()
    
    text = " ".join(wordlist) 
    text = "abandon ability"
    
    # LZW Compression of text
    start = time.time()
    lzw_compressed_data = instance.lzw_encode(text)
    end = time.time()
    
    LZW_encoding_time = end - start
    
    # Build Huffman Frequency Table
    start = time.time()
    freq_table = instance.build_frequency_table(lzw_compressed_data)
    
    # Build Huffman Tree
    huffman_tree = instance.build_huffman_tree(freq_table)
    huffman_codebook, huffman_reverse_codebook = instance.build_huffman_codes(huffman_tree)

    # Huffman Encode the LZW Output
    huffman_compressed_data = instance.huffman_encode(lzw_compressed_data, huffman_codebook)
    
    # Convert the Huffman Output into Bytes
    huffman_compressed_data_bytes = instance.huffman_to_bytes(huffman_compressed_data)

    end = time.time()
    huffman_encoding_time = end - start
    
    # Convert the Bytes into Huffman Output
    start = time.time()
    huffman_compressed_data = instance.bytes_to_huffman(huffman_compressed_data_bytes)
    
    # Convert Huffman Input into LZW Output
    lzw_compressed_data = instance.huffman_decode(huffman_compressed_data, huffman_reverse_codebook)
    end = time.time()
    huffman_decoding_time = end - start
    
    # Decode LZW Input into List of String
    start = time.time()
    decompressed_data = instance.lzw_decode(lzw_compressed_data)
    end= time.time()
    
    LZW_decoding_time = end - start

    # Calculations and Conversions to binary for printing of results.
    hex_output = ''.join(f"\\x{b:02x}" for b in text.encode('utf-8'))
    lzw_compressed_data_bytes = instance.lzw_to_bitstream(lzw_compressed_data)
    
    original_data_size_bytes = sys.getsizeof(text.encode("utf-8"))
    lzw_compressed_data_size_bytes = sys.getsizeof(lzw_compressed_data_bytes)
    huffman_compressed_data_size_bytes = sys.getsizeof(huffman_compressed_data_bytes) 
    compression_ratio = original_data_size_bytes / huffman_compressed_data_size_bytes
    
    # Printing of Results
    print(f"\nOriginal Size: {original_data_size_bytes} Bytes\n")
    print(f"LZW Compressed Size: {lzw_compressed_data_size_bytes} Bytes")
    print(f"LZW Encoding Time: {LZW_encoding_time:.5f} Seconds")
    print(f"LZW Decoding Time: {LZW_decoding_time:.5f} Seconds\n")
    print(f"Huffman Compressed Size: {huffman_compressed_data_size_bytes} Bytes")
    print(f"Huffman Encoding Time {huffman_encoding_time:.5f} Seconds")
    print(f"Huffman Decoding Time {huffman_decoding_time:.5f} Seconds\n")
    print(f"Compression Ratio: {compression_ratio:.2f}x\n\n")
    
    print(f"Original Text: \n{text}\n\n")
    print(f"Decompressed Text: \n{decompressed_data}\n\n")
    
    print(f"Hexadecimal String Original Text: \n{hex_output}")
    print(f"\n\nHexadecimal String Compressed Text: \n{huffman_compressed_data_bytes}")




        
        

    

                