"""
DES Encryption and Decryption - Full Detailed Trace
Students: Reef (446001175) & Reem (446000632)
"""

IP = [
    58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
]

FP = [
    40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
]

E = [
    32,1,2,3,4,5,4,5,6,7,8,9,
    8,9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,
    24,25,26,27,28,29,28,29,30,31,32,1
]

P = [
    16,7,20,21,29,12,28,17,
    1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,
    19,13,30,6,22,11,4,25
]

PC1 = [
    57,49,41,33,25,17,9,
    1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,
    19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,
    7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,
    21,13,5,28,20,12,4
]

PC2 = [
    14,17,11,24,1,5,3,28,
    15,6,21,10,23,19,12,4,
    26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,
    34,53,46,42,50,36,29,32
]

SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

S_BOXES = [
    [
        [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
    ],
    [
        [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
    ],
    [
        [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
    ],
    [
        [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
    ],
    [
        [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
    ],
    [
        [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
    ],
    [
        [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
    ],
    [
        [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
    ]
]


def text_to_bytes(text):
    return list(text.encode("utf-8"))


def bytes_to_text(data):
    return bytes(data).decode("utf-8")


def bytes_to_hex(data):
    return "".join(f"{b:02x}" for b in data)


def bytes_to_bits(data):
    bits = ""
    for byte in data:
        bits += f"{byte:08b}"
    return bits


def bits_to_bytes(bits):
    output = []
    for i in range(0, len(bits), 8):
        output.append(int(bits[i:i+8], 2))
    return output


def bits_to_hex(bits):
    return bytes_to_hex(bits_to_bytes(bits))


def permute(bits, table):
    return "".join(bits[i - 1] for i in table)


def xor_bits(a, b):
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def left_shift(bits, n):
    return bits[n:] + bits[:n]


def pkcs7_padding(data, block_size=8):
    pad_len = block_size - (len(data) % block_size)
    return data + [pad_len] * pad_len


def remove_pkcs7_padding(data):
    pad_len = data[-1]
    return data[:-pad_len]


def print_bits_hex(label, bits):
    print(f"{label} HEX : {bits_to_hex(bits)}")
    print(f"{label} BITS: {bits}")


def generate_round_keys(key_text):
    key_bytes = text_to_bytes(key_text)

    if len(key_bytes) != 8:
        raise ValueError("DES key must be exactly 8 characters / 8 bytes.")

    key_bits = bytes_to_bits(key_bytes)

    print("\n" + "=" * 80)
    print("DES KEY GENERATION")
    print("=" * 80)
    print(f"Key Text: {key_text}")
    print(f"Key Hex : {bytes_to_hex(key_bytes)}")
    print(f"Key Bits: {key_bits}")

    permuted_key = permute(key_bits, PC1)
    print_bits_hex("\nAfter PC-1 56-bit key", permuted_key)

    C = permuted_key[:28]
    D = permuted_key[28:]

    round_keys = []

    for round_num in range(1, 17):
        C = left_shift(C, SHIFTS[round_num - 1])
        D = left_shift(D, SHIFTS[round_num - 1])

        combined = C + D
        round_key = permute(combined, PC2)
        round_keys.append(round_key)

        print("\n" + "-" * 80)
        print(f"ROUND KEY {round_num}")
        print("-" * 80)
        print(f"C{round_num}: {C}")
        print(f"D{round_num}: {D}")
        print_bits_hex(f"K{round_num}", round_key)

    return round_keys


def s_box_substitution(bits48):
    output = ""

    for i in range(8):
        block = bits48[i*6:(i+1)*6]

        row = int(block[0] + block[5], 2)
        col = int(block[1:5], 2)

        value = S_BOXES[i][row][col]
        output += f"{value:04b}"

        print(f"S{i+1}: input={block}, row={row}, col={col}, value={value:02d}, bits={value:04b}")

    return output


def des_function(R, round_key):
    print_bits_hex("Expansion E(R)", permute(R, E))

    expanded_R = permute(R, E)
    xor_result = xor_bits(expanded_R, round_key)

    print_bits_hex("E(R) XOR Round Key", xor_result)

    print("\nS-BOX SUBSTITUTION:")
    sbox_output = s_box_substitution(xor_result)
    print_bits_hex("After S-Boxes 32-bit", sbox_output)

    p_output = permute(sbox_output, P)
    print_bits_hex("After P Permutation", p_output)

    return p_output


def encrypt_block(block, round_keys, block_number):
    print("\n" + "=" * 80)
    print(f"DES ENCRYPTION BLOCK {block_number}")
    print("=" * 80)

    block_bits = bytes_to_bits(block)

    print(f"Plaintext Block Text: {bytes(block)}")
    print(f"Plaintext Block Hex : {bytes_to_hex(block)}")
    print(f"Plaintext Block Bits: {block_bits}")

    ip_bits = permute(block_bits, IP)
    print_bits_hex("\nAfter Initial Permutation IP", ip_bits)

    L = ip_bits[:32]
    R = ip_bits[32:]

    print_bits_hex("L0", L)
    print_bits_hex("R0", R)

    for round_num in range(1, 17):
        print("\n" + "-" * 80)
        print(f"ENCRYPTION ROUND {round_num}")
        print("-" * 80)

        old_L = L
        old_R = R

        print_bits_hex(f"L{round_num-1}", old_L)
        print_bits_hex(f"R{round_num-1}", old_R)
        print_bits_hex(f"K{round_num}", round_keys[round_num - 1])

        f_output = des_function(old_R, round_keys[round_num - 1])

        L = old_R
        R = xor_bits(old_L, f_output)

        print_bits_hex(f"L{round_num}", L)
        print_bits_hex(f"R{round_num}", R)

    combined = R + L

    print_bits_hex("\nBefore Final Permutation R16L16", combined)

    cipher_bits = permute(combined, FP)
    cipher_block = bits_to_bytes(cipher_bits)

    print_bits_hex("After Final Permutation FP", cipher_bits)
    print(f"Ciphertext Block Hex: {bytes_to_hex(cipher_block)}")

    return cipher_block


def decrypt_block(block, round_keys, block_number):
    print("\n" + "=" * 80)
    print(f"DES DECRYPTION BLOCK {block_number}")
    print("=" * 80)

    block_bits = bytes_to_bits(block)

    print(f"Ciphertext Block Hex : {bytes_to_hex(block)}")
    print(f"Ciphertext Block Bits: {block_bits}")

    ip_bits = permute(block_bits, IP)
    print_bits_hex("\nAfter Initial Permutation IP", ip_bits)

    L = ip_bits[:32]
    R = ip_bits[32:]

    print_bits_hex("L0", L)
    print_bits_hex("R0", R)

    reversed_keys = round_keys[::-1]

    for round_num in range(1, 17):
        print("\n" + "-" * 80)
        print(f"DECRYPTION ROUND {round_num}")
        print("-" * 80)

        old_L = L
        old_R = R

        print_bits_hex(f"L{round_num-1}", old_L)
        print_bits_hex(f"R{round_num-1}", old_R)
        print_bits_hex(f"K{17-round_num}", reversed_keys[round_num - 1])

        f_output = des_function(old_R, reversed_keys[round_num - 1])

        L = old_R
        R = xor_bits(old_L, f_output)

        print_bits_hex(f"L{round_num}", L)
        print_bits_hex(f"R{round_num}", R)

    combined = R + L

    print_bits_hex("\nBefore Final Permutation R16L16", combined)

    plain_bits = permute(combined, FP)
    plain_block = bits_to_bytes(plain_bits)

    print_bits_hex("After Final Permutation FP", plain_bits)
    print(f"Recovered Plaintext Block Hex: {bytes_to_hex(plain_block)}")

    return plain_block


def des_encrypt_full(plaintext, key):
    print("=" * 80)
    print("DES ENCRYPTION - FULL DETAILED TRACE")
    print("=" * 80)

    plaintext_bytes = text_to_bytes(plaintext)

    print(f"Plaintext Text: {plaintext}")
    print(f"Plaintext Hex Before Padding: {bytes_to_hex(plaintext_bytes)}")
    print(f"Plaintext Length: {len(plaintext_bytes)} bytes")

    padded_plaintext = pkcs7_padding(plaintext_bytes, 8)

    print(f"Plaintext Hex After Padding : {bytes_to_hex(padded_plaintext)}")
    print(f"Padded Length: {len(padded_plaintext)} bytes")
    print(f"Number of 8-byte DES blocks: {len(padded_plaintext) // 8}")

    round_keys = generate_round_keys(key)

    full_ciphertext = []

    for i in range(0, len(padded_plaintext), 8):
        block = padded_plaintext[i:i+8]
        cipher_block = encrypt_block(block, round_keys, (i // 8) + 1)
        full_ciphertext.extend(cipher_block)

    ciphertext_hex = bytes_to_hex(full_ciphertext)

    print("\n" + "=" * 80)
    print("FINAL DES ENCRYPTION RESULT")
    print("=" * 80)
    print(f"Final Ciphertext Hex: {ciphertext_hex}")

    return ciphertext_hex


def des_decrypt_full(ciphertext_hex, key):
    print("\n" + "=" * 80)
    print("DES DECRYPTION - FULL DETAILED TRACE")
    print("=" * 80)

    ciphertext_bytes = [
        int(ciphertext_hex[i:i+2], 16)
        for i in range(0, len(ciphertext_hex), 2)
    ]

    print(f"Ciphertext Hex: {ciphertext_hex}")
    print(f"Ciphertext Length: {len(ciphertext_bytes)} bytes")
    print(f"Number of 8-byte DES blocks: {len(ciphertext_bytes) // 8}")

    round_keys = generate_round_keys(key)

    full_plaintext = []

    for i in range(0, len(ciphertext_bytes), 8):
        block = ciphertext_bytes[i:i+8]
        plain_block = decrypt_block(block, round_keys, (i // 8) + 1)
        full_plaintext.extend(plain_block)

    plaintext_before_padding_hex = bytes_to_hex(full_plaintext)
    plaintext_without_padding = remove_pkcs7_padding(full_plaintext)
    recovered_text = bytes_to_text(plaintext_without_padding)

    print("\n" + "=" * 80)
    print("FINAL DES DECRYPTION RESULT")
    print("=" * 80)
    print(f"Plaintext Hex Before Removing Padding: {plaintext_before_padding_hex}")
    print(f"Plaintext Hex After Removing Padding : {bytes_to_hex(plaintext_without_padding)}")
    print(f"Recovered Plaintext: {recovered_text}")

    return recovered_text


if __name__ == "__main__":
    plaintext = "Reef446001175Reem446000632"
    key = "44500117"

    ciphertext = des_encrypt_full(plaintext, key)
    recovered_plaintext = des_decrypt_full(ciphertext, key)

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Original Plaintext : {plaintext}")
    print(f"Key                : {key}")
    print(f"Ciphertext Hex     : {ciphertext}")
    print(f"Recovered Plaintext: {recovered_plaintext}")