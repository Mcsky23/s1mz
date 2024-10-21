
def decrypt_data(data):
    encoded = list(data)
    idx = 0
    for i in range(len(data)):

        encoded[i] = (encoded[i] ^ (((((idx << 4) + 97436)) ^ 0x69) & 0xff))
        print(encoded[i])
        if encoded[i] == ord("\n") and (i + 1 < len(data) and (encoded[i + 1] ^ ((((((i + 1) << 4) + 97436)) ^ 0x69) & 0xff)) != ord("\n")):
            idx = -1
        idx += 1


        
    return b"".join([bytes([x]) for x in encoded])


enc = b"\x96\xa4\xb6\xc4\x84\x8f\x9f\x94\xb5\xa6\xc1\xc5\xe4\xfe\x01\x06O"

print(decrypt_data(enc))