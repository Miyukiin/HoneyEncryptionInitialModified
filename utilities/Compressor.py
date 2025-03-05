# python -m utilities.Compressor
# Use LZW -> Huffman Coding -> Bytes to Address Storage Overhead.
from Resources.wordlist import wordlist
from collections import Counter
import heapq
import sys
import pprint
import math
import bitarray

class Compressor():
    def __init__(self):
        self.huffman_root = None
        
    ### lzw METHODS ###
    def lzw_encode(self, text_to_encode:str):
        # Reference Section 5.2 Page 34 of Introduction to Data Compression by Blelloch Guy E.
        
        # Initialize dictionary with single character strings
        dictionary = {chr(i): i for i in range(256)}
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
        def __init__(self, symbol, freq):
            self.symbol = symbol
            self.freq = freq
            self.left = None
            self.right = None

        def __lt__(self, other):
            return self.freq < other.freq
    
    def build_frequency_table(self, data):
        return Counter(data)
    
    def build_huffman_tree(self, freq_table:dict):
        heap = [self.HuffmanNode(symbol, freq) for symbol, freq in freq_table.items()]
        heapq.heapify(heap)

        while len(heap) > 1:
            left = heapq.heappop(heap)
            right = heapq.heappop(heap)
            merged = self.HuffmanNode(None, left.freq + right.freq)
            merged.left = left
            merged.right = right
            heapq.heappush(heap, merged)

        return heap[0]

    def build_huffman_codes(self, node:HuffmanNode, prefix="", codebook:dict={}):
        if node:
            if node.symbol is not None:
                codebook[node.symbol] = prefix
            self.build_huffman_codes(node.left, prefix + "0", codebook)
            self.build_huffman_codes(node.right, prefix + "1", codebook)
        return codebook
    
    def huffman_encode(self, lzw_compressed_data:list[int], codebook:dict):
        self.huffman_encoded_data = "".join(codebook[symbol] for symbol in lzw_compressed_data)
        return self.huffman_encoded_data # Returns a string containing binary numbers.
    
    def huffman_decode(self, huffman_encoded_data, root):
        decoded_data = []
        node:Compressor.HuffmanNode = root

        for bit in huffman_encoded_data:
            node = node.left if bit == "0" else node.right
            if node.symbol is not None:
                decoded_data.append(node.symbol)
                node = root

        return decoded_data
    
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
    
    def compress(self, text):
        # LZW Compress the string of text
        lzw_compressed_data = self.lzw_encode(text)
        
        # Build Huffman Frequency Table
        freq_table = self.build_frequency_table(lzw_compressed_data)
        
        # Build Huffman Tree
        huffman_root = self.build_huffman_tree(freq_table)
        huffman_codebook = self.build_huffman_codes(huffman_root)
        
        self.huffman_root = huffman_root

        # Huffman Encode the LZW Output
        huffman_compressed_data = self.huffman_encode(lzw_compressed_data, huffman_codebook)
        
        # Binary Encode the Huffman Output
        binary_compressed_data = self.huffman_to_bytes(huffman_compressed_data)
        
        return binary_compressed_data
    
    def decompress(self, binary_compressed_data):
        # Convert Binary Input into Huffman Output
        huffman_compressed_data = instance.bytes_to_huffman(binary_compressed_data)
        
        # Convert Huffman Input into LZW Output
        if self.huffman_root is None:
            raise AssertionError("Huffman Root is None. Call compress function first.")
        
        lzw_compressed_data = instance.huffman_decode(huffman_compressed_data, self.huffman_root)
        
        # Decode LZW Input into String
        decompressed_data = instance.lzw_decode(lzw_compressed_data)
        
        # Construct List, using whitespace as separator.
        decompressed_data = decompressed_data.split()
        
        return decompressed_data

  
if __name__ == "__main__":
    instance = Compressor()
    
    text = " ".join(wordlist) 

    lzw_compressed_data = instance.lzw_encode(text)
    
    # Build Huffman Frequency Table
    freq_table = instance.build_frequency_table(lzw_compressed_data)
    
    # Build Huffman Tree
    huffman_root = instance.build_huffman_tree(freq_table)
    huffman_codebook = instance.build_huffman_codes(huffman_root)

    # Huffman Encode the LZW Output
    huffman_compressed_data = instance.huffman_encode(lzw_compressed_data, huffman_codebook)
    
    # Convert the Huffman Output into Bytes
    huffman_compressed_data_bytes = instance.huffman_to_bytes(huffman_compressed_data)

    # Convert the Bytes into Huffman Output
    huffman_compressed_data = instance.bytes_to_huffman(huffman_compressed_data_bytes)
    
    # Convert Huffman Input into LZW Output
    lzw_compressed_data = instance.huffman_decode(huffman_compressed_data, huffman_root)
    
    # Decode LZW Input into List of String
    decompressed_data = instance.lzw_decode(lzw_compressed_data)

    # Calculations and Conversions to binary for printing of results.
    hex_output = ''.join(f"\\x{b:02x}" for b in text.encode('utf-8'))
    lzw_compressed_data_bytes = instance.lzw_to_bitstream(lzw_compressed_data)
    
    original_data_size_bytes = sys.getsizeof(text.encode("utf-8"))
    lzw_compressed_data_size_bytes = sys.getsizeof(lzw_compressed_data_bytes)
    huffman_compressed_data_size_bytes = sys.getsizeof(huffman_compressed_data_bytes) 
    compression_ratio = original_data_size_bytes / huffman_compressed_data_size_bytes
    
    # Printing of Results
    print(f"Original Size: {original_data_size_bytes} Bytes")
    print(f"LZW Compressed Size: {lzw_compressed_data_size_bytes} Bytes")
    print(f"Huffman Compressed Size: {huffman_compressed_data_size_bytes} Bytes\n")
    print(f"\nCompression Ratio: {compression_ratio:.2f}x")
    
    print(f"Original Text: \n{text}\n")
    print(f"Decompressed Text: \n{decompressed_data}\n")
    
    print(f"Hexadecimal String Original Text: \n{hex_output}" )
    print(f"\n\nHexadecimal String Compressed Text: \n{huffman_compressed_data_bytes}")




        
        

    

                