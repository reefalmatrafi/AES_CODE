"""
AES-128 Encryption WITHOUT NumPy - Pure Python Implementation
Students: Reef (446001175) & Reem (446000632)
"""

# Correct AES S-box
S_BOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
INV_S_BOX = [0] * 256
for i in range(256):
    INV_S_BOX[S_BOX[i]] = i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


def text_to_bytes(text):
    return list(text.encode("utf-8"))


def bytes_to_hex(data):
    return ''.join(f'{b:02x}' for b in data)


def pkcs7_padding(data):
    pad_len = 16 - (len(data) % 16)
    return data + [pad_len] * pad_len


def bytes_to_state(block):
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = block[i]
    return state


def state_to_bytes(state):
    output = []
    for col in range(4):
        for row in range(4):
            output.append(state[row][col])
    return output


def state_to_hex(state):
    return bytes_to_hex(state_to_bytes(state))


def print_state(state, label):
    print(f"\n{label}:")
    for row in range(4):
        print(" ".join(f"{state[row][col]:02x}" for col in range(4)))


def sub_bytes(state):
    return [[S_BOX[state[row][col]] for col in range(4)] for row in range(4)]


def shift_rows(state):
    new_state = [row[:] for row in state]
    new_state[1] = state[1][1:] + state[1][:1]
    new_state[2] = state[2][2:] + state[2][:2]
    new_state[3] = state[3][3:] + state[3][:3]
    return new_state
def inv_sub_bytes(state):
    return [[INV_S_BOX[state[row][col]] for col in range(4)] for row in range(4)]


def inv_shift_rows(state):
    new_state = [row[:] for row in state]
    new_state[1] = state[1][-1:] + state[1][:-1]
    new_state[2] = state[2][-2:] + state[2][:-2]
    new_state[3] = state[3][-3:] + state[3][:-3]
    return new_state


def inv_mix_columns(state):
    new_state = [[0] * 4 for _ in range(4)]

    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        new_state[0][col] = gmul(0x0e, s0) ^ gmul(0x0b, s1) ^ gmul(0x0d, s2) ^ gmul(0x09, s3)
        new_state[1][col] = gmul(0x09, s0) ^ gmul(0x0e, s1) ^ gmul(0x0b, s2) ^ gmul(0x0d, s3)
        new_state[2][col] = gmul(0x0d, s0) ^ gmul(0x09, s1) ^ gmul(0x0e, s2) ^ gmul(0x0b, s3)
        new_state[3][col] = gmul(0x0b, s0) ^ gmul(0x0d, s1) ^ gmul(0x09, s2) ^ gmul(0x0e, s3)

    return new_state


def remove_pkcs7_padding(data):
    pad_len = data[-1]
    return data[:-pad_len]

def gmul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xff
        if high_bit:
            a ^= 0x1b
        b >>= 1
    return result


def mix_columns(state):
    new_state = [[0] * 4 for _ in range(4)]

    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        new_state[0][col] = gmul(0x02, s0) ^ gmul(0x03, s1) ^ s2 ^ s3
        new_state[1][col] = s0 ^ gmul(0x02, s1) ^ gmul(0x03, s2) ^ s3
        new_state[2][col] = s0 ^ s1 ^ gmul(0x02, s2) ^ gmul(0x03, s3)
        new_state[3][col] = gmul(0x03, s0) ^ s1 ^ s2 ^ gmul(0x02, s3)

    return new_state


def add_round_key(state, round_key):
    return [
        [state[row][col] ^ round_key[row][col] for col in range(4)]
        for row in range(4)
    ]


def key_expansion(key_text):
    key_bytes = text_to_bytes(key_text)

    if len(key_bytes) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes / 16 characters.")

    words = []
    for i in range(4):
        words.append(key_bytes[4*i:4*i+4])

    for i in range(4, 44):
        temp = words[i - 1][:]

        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [S_BOX[b] for b in temp]
            temp[0] ^= RCON[(i // 4) - 1]

        new_word = [words[i - 4][j] ^ temp[j] for j in range(4)]
        words.append(new_word)

    round_keys = []

    for round_num in range(11):
        round_key_bytes = []
        for i in range(4):
            round_key_bytes.extend(words[round_num * 4 + i])
        round_keys.append(bytes_to_state(round_key_bytes))

    return round_keys


def encrypt_block(block, round_keys, block_number):
    state = bytes_to_state(block)

    print("\n" + "=" * 80)
    print(f"BLOCK {block_number}")
    print("=" * 80)
    print(f"Block plaintext hex: {bytes_to_hex(block)}")
    print_state(state, "Initial State Matrix")

    print_state(round_keys[0], "Round Key 0")
    state = add_round_key(state, round_keys[0])
    print_state(state, "After Initial AddRoundKey")

    for round_num in range(1, 11):
        print("\n" + "-" * 80)
        print(f"ROUND {round_num}")
        print("-" * 80)

        state = sub_bytes(state)
        print_state(state, "After SubBytes")

        state = shift_rows(state)
        print_state(state, "After ShiftRows")

        if round_num != 10:
            state = mix_columns(state)
            print_state(state, "After MixColumns")
        else:
            print("\nMixColumns: SKIPPED in final round")

        print_state(round_keys[round_num], f"Round Key {round_num}")

        state = add_round_key(state, round_keys[round_num])
        print_state(state, "After AddRoundKey")

    ciphertext_block = state_to_bytes(state)
    print(f"\nBlock {block_number} Ciphertext Hex: {bytes_to_hex(ciphertext_block)}")

    return ciphertext_block
def decrypt_block(block, round_keys, block_number):
    state = bytes_to_state(block)

    print("\n" + "=" * 80)
    print(f"DECRYPTION BLOCK {block_number}")
    print("=" * 80)
    print(f"Ciphertext block hex: {bytes_to_hex(block)}")
    print_state(state, "Initial Ciphertext State Matrix")

    print_state(round_keys[10], "Round Key 10")
    state = add_round_key(state, round_keys[10])
    print_state(state, "After Initial AddRoundKey")

    for round_num in range(9, -1, -1):
        print("\n" + "-" * 80)
        print(f"DECRYPTION ROUND {10 - round_num}")
        print("-" * 80)

        state = inv_shift_rows(state)
        print_state(state, "After InvShiftRows")

        state = inv_sub_bytes(state)
        print_state(state, "After InvSubBytes")

        print_state(round_keys[round_num], f"Round Key {round_num}")

        state = add_round_key(state, round_keys[round_num])
        print_state(state, "After AddRoundKey")

        if round_num != 0:
            state = inv_mix_columns(state)
            print_state(state, "After InvMixColumns")
        else:
            print("\nInvMixColumns: SKIPPED in final decryption round")

    plaintext_block = state_to_bytes(state)
    print(f"\nBlock {block_number} Plaintext Hex: {bytes_to_hex(plaintext_block)}")

    return plaintext_block


def aes_128_decrypt(ciphertext_hex, key):
    print("\n" + "=" * 80)
    print("AES-128 DECRYPTION - FULL DETAILED TRACE")
    print("=" * 80)

    key_bytes = text_to_bytes(key)

    if len(key_bytes) != 16:
        raise ValueError("Your key must be exactly 16 characters for AES-128.")

    ciphertext_bytes = [
        int(ciphertext_hex[i:i+2], 16)
        for i in range(0, len(ciphertext_hex), 2)
    ]

    print(f"Ciphertext Hex: {ciphertext_hex}")
    print(f"Key: {key}")
    print(f"Key Hex: {bytes_to_hex(key_bytes)}")
    print(f"Ciphertext length: {len(ciphertext_bytes)} bytes")
    print(f"Number of 16-byte blocks: {len(ciphertext_bytes) // 16}")

    round_keys = key_expansion(key)

    full_plaintext = []

    for block_index in range(0, len(ciphertext_bytes), 16):
        block = ciphertext_bytes[block_index:block_index + 16]
        decrypted_block = decrypt_block(
            block,
            round_keys,
            block_number=(block_index // 16) + 1
        )
        full_plaintext.extend(decrypted_block)

    plaintext_without_padding = remove_pkcs7_padding(full_plaintext)
    plaintext_text = bytes(plaintext_without_padding).decode("utf-8")

    print("\n" + "=" * 80)
    print("FINAL DECRYPTION RESULT")
    print("=" * 80)
    print(f"Plaintext Hex Before Removing Padding: {bytes_to_hex(full_plaintext)}")
    print(f"Plaintext Hex After Removing Padding:  {bytes_to_hex(plaintext_without_padding)}")
    print(f"Recovered Plaintext: {plaintext_text}")

    return plaintext_text

def aes_128_encrypt(plaintext, key):
    print("=" * 80)
    print("AES-128 ENCRYPTION - FULL DETAILED TRACE")
    print("=" * 80)

    print("Student A: Reef (ID: 446001175)")
    print("Student B: Reem (ID: 446000632)")
    print(f"\nPlaintext: {plaintext}")
    print(f"Key: {key}")

    plaintext_bytes = text_to_bytes(plaintext)
    key_bytes = text_to_bytes(key)

    print(f"\nPlaintext length: {len(plaintext_bytes)} bytes")
    print(f"Key length: {len(key_bytes)} bytes")

    if len(key_bytes) != 16:
        raise ValueError("Your key must be exactly 16 characters for AES-128.")

    print(f"\nPlaintext Hex Before Padding: {bytes_to_hex(plaintext_bytes)}")

    padded_plaintext = pkcs7_padding(plaintext_bytes)

    print(f"Plaintext Hex After Padding:  {bytes_to_hex(padded_plaintext)}")
    print(f"Padded length: {len(padded_plaintext)} bytes")
    print(f"Number of 16-byte blocks: {len(padded_plaintext) // 16}")

    print(f"\nKey Hex: {bytes_to_hex(key_bytes)}")

    round_keys = key_expansion(key)

    print("\n" + "=" * 80)
    print("GENERATED ROUND KEYS")
    print("=" * 80)

    for i, rk in enumerate(round_keys):
        print_state(rk, f"Round Key {i}")

    full_ciphertext = []

    for block_index in range(0, len(padded_plaintext), 16):
        block = padded_plaintext[block_index:block_index + 16]
        encrypted_block = encrypt_block(
            block,
            round_keys,
            block_number=(block_index // 16) + 1
        )
        full_ciphertext.extend(encrypted_block)

    ciphertext_hex = bytes_to_hex(full_ciphertext)

    print("\n" + "=" * 80)
    print("FINAL RESULT")
    print("=" * 80)
    print(f"Final Ciphertext Hex: {ciphertext_hex}")

    return ciphertext_hex


if __name__ == "__main__":
    plaintext = "Reef446001175Reem446000632"
    key = "reef2026secure!!"

    ciphertext = aes_128_encrypt(plaintext, key)

    recovered_plaintext = aes_128_decrypt(ciphertext, key)

    print("\nSUMMARY:")
    print(f"Original Plaintext:  {plaintext}")
    print(f"Key:                 {key}")
    print(f"Ciphertext:          {ciphertext}")
    print(f"Recovered Plaintext: {recovered_plaintext}")