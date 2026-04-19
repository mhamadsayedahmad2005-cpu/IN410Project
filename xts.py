from saes import encrypt, decrypt

# Fixed keys
k1 = 66
k2 = 99


# -----------------------------
# Helper functions
# -----------------------------

def xor(a: int, b: int) -> int:
    return a ^ b


def split_blocks(data: str):
    blocks = []
    for i in range(0, len(data), 2):
        block = data[i:i+2]
        if len(block) < 2:
            block += " "
        blocks.append(int.from_bytes(block.encode("utf-8"), "big"))
    return blocks


def blocks_to_text(blocks):
    text = ""
    for b in blocks:
        try:
            text += b.to_bytes(2, "big").decode("utf-8", errors="ignore")
        except OverflowError:
            text += "??"
    return text.rstrip()


def format_blocks_decimal(blocks):
    return "[" + ", ".join(str(b) for b in blocks) + "]"


def format_blocks_hex(blocks):
    return "[" + ", ".join(f"0x{b:04X}" for b in blocks) + "]"


def parse_ciphertext(cipher_str: str):
    """
    Accepts:
      1) Decimal list: 12345, 54321, 999
      2) Hex list: 0x1234, 0xABCD
      3) Mixed whitespace / commas
    """
    cipher_str = cipher_str.strip()
    if not cipher_str:
        return []

    parts = [p.strip() for p in cipher_str.replace("[", "").replace("]", "").split(",")]
    blocks = []

    for p in parts:
        if not p:
            continue
        if p.lower().startswith("0x"):
            blocks.append(int(p, 16))
        else:
            blocks.append(int(p))

    return blocks


# -----------------------------
# XTS Encryption
# -----------------------------

def xts_encrypt(text: str, K1: int = k1, K2: int = k2):
    blocks = split_blocks(text)
    ciphertext = []

    for i, block in enumerate(blocks):
        tweak = encrypt(i, K2)
        temp = xor(block, tweak)
        encrypted = encrypt(temp, K1)
        c = xor(encrypted, tweak)
        ciphertext.append(c)

    return ciphertext


# -----------------------------
# XTS Decryption
# -----------------------------

def xts_decrypt(cipher_blocks, K1: int = k1, K2: int = k2):
    plaintext_blocks = []

    for i, block in enumerate(cipher_blocks):
        tweak = encrypt(i, K2)
        temp = xor(block, tweak)
        decrypted = decrypt(temp, K1)
        p = xor(decrypted, tweak)
        plaintext_blocks.append(p)

    return blocks_to_text(plaintext_blocks)


# -----------------------------
# Demo / Interactive mode
# -----------------------------

if __name__ == "__main__":
    print("Using fixed keys:")
    print("k1 =", k1)
    print("k2 =", k2)

    print("\nChoose mode:")
    print("1. Encrypt plaintext")
    print("2. Decrypt ciphertext")
    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        plaintext = input("Enter plaintext: ")
        cipher = xts_encrypt(plaintext)

        print("\n--- Encryption Result ---")
        print("Plaintext :", plaintext)
        print("Ciphertext (decimal):", format_blocks_decimal(cipher))
        print("Ciphertext (hex)    :", format_blocks_hex(cipher))

        recovered = xts_decrypt(cipher)
        print("Decrypted check     :", recovered)

    elif choice == "2":
        cipher_input = input(
            "Enter ciphertext blocks\n"
            "Examples:\n"
            "  12345, 54321, 9999\n"
            "  0x1A2B, 0x00FF, 0xABCD\n"
            "> "
        )

        try:
            cipher_blocks = parse_ciphertext(cipher_input)
            decrypted = xts_decrypt(cipher_blocks)

            print("\n--- Decryption Result ---")
            print("Ciphertext:", cipher_blocks)
            print("Decrypted :", decrypted)

        except ValueError as e:
            print(f"Invalid ciphertext format: {e}")

    else:
        print("Invalid choice.")