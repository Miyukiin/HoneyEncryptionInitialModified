import base64

def format_bitstuffing(BinaryText): 
    encoded_messages = []
    for word in BinaryText:
        base64_encoded = base64.b64encode(word.encode("ascii"))
        base64_message = base64_encoded.decode("ascii")
        encoded_messages.append(base64_message)

    return "MTDz". join(encoded_messages)



