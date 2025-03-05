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
    text = """
    According to Tech Jury, despite a number of cool apps and tips for successful time management, only 17 of people track their time. 50 of people have never thought about time waste, even though they are always late and running out of time. Time management is a skill. It helps people handle their daily duties without burnout and severe exhaustion. The N.I.L.C. includes time management on the list of top ten demanded soft skills that employees require in 2022. Why is it so important to manage one\'s time correctly? Stephen Covey once said, \"The key is not spending time, but in investing it\". It means that proper timing guarantees a person\'s success in many life areas.

Career Trend names three negative aspects that occur when a person is not able to follow a schedule and be flexible. First off, one risks delaying the task performance all the time. People who got used to procrastination start doing assignments and duties at the very last moment. As a result, they sacrifice quality for the sake of deadlines. Moreover, procrastination is a perfect killer of vital energy and productiveness that are so essential in the XXI century. The second aspect is the development of a chronic late-coming habit. How can one come somewhere on time if a person cannot plan activities? Besides, late-coming and procrastination lead to the third negative aspect. It is a daily overload that results in burnout. When nothing is well-planned, people always get busy with something, go to bed late, and cannot relax. The pressure of undone tasks prevents them from normal sleep and rest. As a result, they acquire panic attacks, anxiety, sleep disorders, apathy, or depression.

Mindtools introduces five benefits that people face when managing their day successfully. To begin with, such people are known as productive and effective in what they do. Employers adore such individuals because they handle many tasks faster than other employees. Secondly, ideal time managers almost never feel stressed at work. They know what they have to do and how much time they require for that. Third, scheduling is the best promoter. For example, if a student has free time after having done academic homework, it will be possible to broaden one's look. Such a student can read books to enlarge personal vocabulary, practice in report or article writing, visit different places, and meet new people for networking. All these things lead to the next benefit which is a positive reputation. Motivated individuals with perfect timing skills usually become a model for following. Finally, perfect time managers have more chances to succeed in life than time wasters. Those who control their time can control and supervise others.
What can a person do to learn proper scheduling? Professionals give seven tips that can help everyone get more control over time. The first one is to set goals. Motivation is an ignition key. Moreover, the goal is to be achievable. If a person is bad at Geometry and the creation of new things, it is better not to dream about becoming a top designer. The next task is to learn prioritizing concepts. People often do tasks that can be done later but delay duties that should be done here and right now. Moreover, they often neglect tasks that are long-perspective. For example, a person needs to master a second language to get the desired occupation. She does other tasks but forgets to memorize new words and practice daily. As a result, she will not get the job because language mastering demands more than one day. The next recommendation is to set time frames for each task and try not to change them. When a person sees the approaching deadline, he speeds up a bit and stops delaying duties. Another essential thing is to have rest. Brains and human bodies, in general, cannot function well when being exhausted. Everybody knows that 20 minutes of noon sleep restores vital energy that helps to handle tasks in the second half of the day. Except for bedtime, one needs to enjoy a hobby or a pleasant activity.

The best method to stay on alert is to have a notebook or install an app such as Todoist, TimeTree, etc. A benefit of a notebook is that a person deals only with scheduling and jotting down without being distracted by messages and notifications. The benefits of apps are their notification systems and compact seizes of compatible devices. Besides, one never forgets a smartphone at home. By the way, 33 of individuals worldwide use Todoist to handle their daily duties. It is also possible to use the wall, online or mobile calendars. One can mark important meetings and tasks there. A system will send reminders, and a person will not forget about the upcoming event. Finally, one should plan everything in advance. It is a bad idea to start a day with a mess in one\'s head. Psychologists recommend scheduling in the evening to have a set-up mind in the morning.

An extra tip for beginners might be sharing duties and avoiding extra work. For example, a person must make a team project. All members should take equal responsibilities to guarantee their on-time performance. If a friend asks an exhausted student to help, it will be better to excuse and refuse extra tasks. Otherwise, a friend will succeed while a student will fail.

The above-mentioned facts and tips highlight the importance of good time management. When people are not constantly in a hurry, they cope with many tasks and feel self-confident. They are not afraid of the coming day that brings more responsibilities and duties. Such people know how to turn a minute into a successful life investment. Perfect time managers are not lazy. They are productive and full of energy. Leading organizations and companies desire to get such individuals in their teams to boost overall productivity. Proper scheduling lets people be perfect leaders, team builders, assistants, and performers. As William Shakespear once said, \"Better to be three hours to noon, than a minute too late\".
    """

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
    print(f"\nOriginal Size: {original_data_size_bytes} Bytes")
    print(f"LZW Compressed Size: {lzw_compressed_data_size_bytes} Bytes")
    print(f"Huffman Compressed Size: {huffman_compressed_data_size_bytes} Bytes\n")
    print(f"Compression Ratio: {compression_ratio:.2f}x\n\n")
    
    print(f"Original Text: \n{text}\n\n")
    print(f"Decompressed Text: \n{decompressed_data}\n\n")
    
    print(f"Hexadecimal String Original Text: \n{hex_output}")
    print(f"\n\nHexadecimal String Compressed Text: \n{huffman_compressed_data_bytes}")




        
        

    

                