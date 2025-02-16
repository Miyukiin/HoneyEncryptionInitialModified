import base64
#import format_bitstuff



def format_destuff(final_encoded_messages):
    encoded_messages = final_encoded_messages.split("MTDz")
    decoded_messages = []
    for encoded_message in encoded_messages:
        base64_decoded = base64.b64decode(encoded_message)
        decoded_message = base64_decoded.decode("ascii")
        decoded_messages.append(decoded_message)

    return decoded_messages
    
