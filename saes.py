# -----------------------------
# S-AES Implementation
# -----------------------------

# S-Box and Inverse S-Box
SBOX = {
    0x0: 0x9, 0x1: 0x4, 0x2: 0xA, 0x3: 0xB,
    0x4: 0xD, 0x5: 0x1, 0x6: 0x8, 0x7: 0x5,
    0x8: 0x6, 0x9: 0x2, 0xA: 0x0, 0xB: 0x3,
    0xC: 0xC, 0xD: 0xE, 0xE: 0xF, 0xF: 0x7
}

INV_SBOX = {v: k for k, v in SBOX.items()}

RCON1 = 0b10000000
RCON2 = 0b00110000


# -----------------------------
# Helper Functions
# -----------------------------

def sub_nib(byte):
    left = (byte >> 4) & 0xF
    right = byte & 0xF
    return (SBOX[left] << 4) | SBOX[right]


def inv_sub_nib(byte):
    left = (byte >> 4) & 0xF
    right = byte & 0xF
    return (INV_SBOX[left] << 4) | INV_SBOX[right]


def rot_nib(byte):
    return ((byte << 4) | (byte >> 4)) & 0xFF


def int_to_nibbles(x):
    return [
        (x >> 12) & 0xF,
        (x >> 8) & 0xF,
        (x >> 4) & 0xF,
        x & 0xF
    ]


def nibbles_to_int(n):
    return (n[0] << 12) | (n[1] << 8) | (n[2] << 4) | n[3]


# -----------------------------
# Galois Field Multiplication
# -----------------------------

def gmul(a, b):
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        hi = a & 0x8
        a <<= 1
        if hi:
            a ^= 0x13
        b >>= 1
    return p & 0xF


# -----------------------------
# Core Transformations
# -----------------------------

def sub_nibbles(state):
    return [SBOX[n] for n in state]


def inv_sub_nibbles(state):
    return [INV_SBOX[n] for n in state]


def shift_rows(state):
    return [state[0], state[1], state[3], state[2]]


def inv_shift_rows(state):
    return [state[0], state[1], state[3], state[2]]  # same for 2x2


def mix_columns(state):
    return [
        state[0] ^ gmul(4, state[2]),
        state[1] ^ gmul(4, state[3]),
        state[2] ^ gmul(4, state[0]),
        state[3] ^ gmul(4, state[1]),
    ]


def inv_mix_columns(state):
    return [
        gmul(9, state[0]) ^ gmul(2, state[2]),
        gmul(9, state[1]) ^ gmul(2, state[3]),
        gmul(9, state[2]) ^ gmul(2, state[0]),
        gmul(9, state[3]) ^ gmul(2, state[1]),
    ]


# -----------------------------
# Key Expansion
# -----------------------------

def key_expansion(key):
    w0 = (key >> 8) & 0xFF
    w1 = key & 0xFF

    w2 = w0 ^ (sub_nib(rot_nib(w1)) ^ RCON1)
    w3 = w2 ^ w1

    w4 = w2 ^ (sub_nib(rot_nib(w3)) ^ RCON2)
    w5 = w4 ^ w3

    K0 = (w0 << 8) | w1
    K1 = (w2 << 8) | w3
    K2 = (w4 << 8) | w5

    return K0, K1, K2


# -----------------------------
# Encryption
# -----------------------------

def encrypt(plaintext, key):
    K0, K1, K2 = key_expansion(key)

    # Round 0
    state = plaintext ^ K0

    # Round 1
    state = int_to_nibbles(state)
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = nibbles_to_int(state) ^ K1

    # Round 2
    state = int_to_nibbles(state)
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = nibbles_to_int(state) ^ K2

    return state


# -----------------------------
# Decryption
# -----------------------------

def decrypt(ciphertext, key):
    K0, K1, K2 = key_expansion(key)

    # Round 2 (reverse)
    state = ciphertext ^ K2
    state = int_to_nibbles(state)
    state = inv_shift_rows(state)
    state = inv_sub_nibbles(state)

    # Round 1 (reverse)
    state = nibbles_to_int(state) ^ K1
    state = int_to_nibbles(state)
    state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_nibbles(state)

    # Round 0
    state = nibbles_to_int(state) ^ K0

    return state


# -----------------------------
# TEST
# -----------------------------
if __name__ == "__main__":
    P = 0b1101011100101000
    K = 0b0100101011110101

    C = encrypt(P, K)
    D = decrypt(C, K)

    print("Plaintext :", bin(P))
    print("Ciphertext:", bin(C))
    print("Decrypted :", bin(D))
