# Sbox
GIFT_S = [1, 10, 4, 12, 6, 15, 3, 9, 2, 13, 11, 7, 5, 0, 8, 14]
GIFT_S_inv = [13, 0, 8, 6, 2, 12, 4, 11, 14, 7, 1, 10, 3, 9, 15, 5]

# Bit permutation
GIFT_P = [
    # Block size = 64
    0, 17, 34, 51, 48, 1, 18, 35, 32, 49, 2, 19, 16, 33, 50, 3,
    4, 21, 38, 55, 52, 5, 22, 39, 36, 53, 6, 23, 20, 37, 54, 7,
    8, 25, 42, 59, 56, 9, 26, 43, 40, 57, 10, 27, 24, 41, 58, 11,
    12, 29, 46, 63, 60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15
]

GIFT_P_inv = [
    # Block size = 64
    0, 5, 10, 15, 16, 21, 26, 31, 32, 37, 42, 47, 48, 53, 58, 63,
    12, 1, 6, 11, 28, 17, 22, 27, 44, 33, 38, 43, 60, 49, 54, 59,
    8, 13, 2, 7, 24, 29, 18, 23, 40, 45, 34, 39, 56, 61, 50, 55,
    4, 9, 14, 3, 20, 25, 30, 19, 36, 41, 46, 35, 52, 57, 62, 51
]

# Round constants
GIFT_RC = [
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
    0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
    0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
    0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
    0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04, 0x09, 0x13,
    0x26, 0x0C, 0x19, 0x32, 0x25, 0x0A, 0x15, 0x2A, 0x14, 0x28,
    0x10, 0x20
]

def enc64(input_bytes, masterkey, no_of_rounds, print_details):
    key = masterkey[:32]  # Copy masterkey

    bits = [0] * 64
    perm_bits = [0] * 64
    key_bits = [0] * 128
    temp_key = [0] * 32

    for r in range(no_of_rounds):
        # SubCells
        for i in range(16):
            input_bytes[i] = GIFT_S[input_bytes[i]]

        # PermBits
        for i in range(16):
            for j in range(4):
                bits[4 * i + j] = (input_bytes[i] >> j) & 0x1
        for i in range(64):
            perm_bits[GIFT_P[i]] = bits[i]
        for i in range(16):
            input_bytes[i] = 0
            for j in range(4):
                input_bytes[i] ^= perm_bits[4 * i + j] << j

        # AddRoundKey
        for i in range(16):
            for j in range(4):
                bits[4 * i + j] = (input_bytes[i] >> j) & 0x1
        for i in range(32):
            for j in range(4):
                key_bits[4 * i + j] = (key[i] >> j) & 0x1
        kbc = 0
        for i in range(16):
            bits[4 * i] ^= key_bits[kbc]
            bits[4 * i + 1] ^= key_bits[kbc + 16]
            kbc += 1
        bits[3] ^= GIFT_RC[r] & 0x1
        bits[7] ^= (GIFT_RC[r] >> 1) & 0x1
        bits[11] ^= (GIFT_RC[r] >> 2) & 0x1
        bits[15] ^= (GIFT_RC[r] >> 3) & 0x1
        bits[19] ^= (GIFT_RC[r] >> 4) & 0x1
        bits[23] ^= (GIFT_RC[r] >> 5) & 0x1
        bits[63] ^= 1
        for i in range(16):
            input_bytes[i] = 0
            for j in range(4):
                input_bytes[i] ^= bits[4 * i + j] << j

        # Key update
        temp_key = key[8:] + key[:8]
        key[:24] = temp_key[:24]
        key[24:28] = [temp_key[27], temp_key[24], temp_key[25], temp_key[26]]
        key[28:32] = [
            ((temp_key[28] & 0xC) >> 2) | ((temp_key[29] & 0x3) << 2),
            ((temp_key[29] & 0xC) >> 2) | ((temp_key[30] & 0x3) << 2),
            ((temp_key[30] & 0xC) >> 2) | ((temp_key[31] & 0x3) << 2),
            ((temp_key[31] & 0xC) >> 2) | ((temp_key[28] & 0x3) << 2),
        ]

    return input_bytes

def dec64(input_bytes, masterkey, no_of_rounds, print_details):
    key = masterkey[:32]  # Copy masterkey

    # Compute and store the round keys
    round_key_state = [[0] * 32 for _ in range(no_of_rounds)]
    bits = [0] * 64
    perm_bits = [0] * 64
    key_bits = [0] * 128
    temp_key = [0] * 32

    for r in range(no_of_rounds):
        # Copy the key state
        round_key_state[r] = key[:]

        # Key update
        temp_key = key[8:] + key[:8]  # Entire key >> 32
        key[:24] = temp_key[:24]
        key[24:28] = [temp_key[27], temp_key[24], temp_key[25], temp_key[26]]  # k0 >> 12
        key[28:32] = [
            ((temp_key[28] & 0xC) >> 2) | ((temp_key[29] & 0x3) << 2),
            ((temp_key[29] & 0xC) >> 2) | ((temp_key[30] & 0x3) << 2),
            ((temp_key[30] & 0xC) >> 2) | ((temp_key[31] & 0x3) << 2),
            ((temp_key[31] & 0xC) >> 2) | ((temp_key[28] & 0x3) << 2),
        ]

    for r in range(no_of_rounds - 1, -1, -1):
        # AddRoundKey
        for i in range(16):
            for j in range(4):
                bits[4 * i + j] = (input_bytes[i] >> j) & 0x1
        for i in range(32):
            for j in range(4):
                key_bits[4 * i + j] = (round_key_state[r][i] >> j) & 0x1

        kbc = 0  # Key bit counter
        for i in range(16):
            bits[4 * i] ^= key_bits[kbc]
            bits[4 * i + 1] ^= key_bits[kbc + 16]
            kbc += 1

        # Add constant
        bits[3] ^= GIFT_RC[r] & 0x1
        bits[7] ^= (GIFT_RC[r] >> 1) & 0x1
        bits[11] ^= (GIFT_RC[r] >> 2) & 0x1
        bits[15] ^= (GIFT_RC[r] >> 3) & 0x1
        bits[19] ^= (GIFT_RC[r] >> 4) & 0x1
        bits[23] ^= (GIFT_RC[r] >> 5) & 0x1
        bits[63] ^= 1

        for i in range(16):
            input_bytes[i] = 0
            for j in range(4):
                input_bytes[i] ^= bits[4 * i + j] << j

        # PermBits
        for i in range(16):
            for j in range(4):
                bits[4 * i + j] = (input_bytes[i] >> j) & 0x1
        for i in range(64):
            perm_bits[GIFT_P_inv[i]] = bits[i]
        for i in range(16):
            input_bytes[i] = 0
            for j in range(4):
                input_bytes[i] ^= perm_bits[4 * i + j] << j

        # SubCells
        for i in range(16):
            input_bytes[i] = GIFT_S_inv[input_bytes[i]]

    return input_bytes
import random
import time

def main():
    random.seed(int(time.time()))

    # Generate random plaintext (P) and master key (K)
    P = [random.randint(0, 0xf) for _ in range(16)]
    K = [random.randint(0, 0xf) for _ in range(32)]
    # Print plaintext
    print("Plaintext = ", end="")

    for i in range(16):
        print(f"{P[15 - i]:x}", end="")
        if i % 2 == 1:
            print(" ", end="")


    # Print master key
    print("Masterkey = ", end="")
    for i in range(32):
        print(f"{K[31 - i]:x}", end="")
        if i % 2 == 1:
            print(" ", end="")
    print("\n")

    # Encrypt
    enc64(P, K, 28, True)

    # Print ciphertext
    print("Ciphertext = ", end="")
    for i in range(16):
        print(f"{P[15 - i]:x}", end="")
        if i % 2 == 1:
            print(" ", end="")
    print("\n")

    # Decrypt
    dec64(P, K, 28, True)

    # Print plaintext after decryption
    print("Plaintext = ", end="")
    for i in range(16):
        print(f"{P[15 - i]:x}", end="")
        if i % 2 == 1:
            print(" ", end="")
    print()

if __name__ == "__main__":
    main()

