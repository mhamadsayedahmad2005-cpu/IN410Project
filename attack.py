from xts import k1, k2, xts_decrypt, parse_ciphertext, format_blocks_decimal, format_blocks_hex

print("=== XTS Decryption Mode ===")

cipher_input = input(
    "Enter ciphertext blocks\n"
    "Examples:\n"
    "  12345, 54321, 9999\n"
    "  0x1A2B, 0x00FF, 0xABCD\n"
    "> "
)

try:
    cipher_blocks = parse_ciphertext(cipher_input)
    plaintext = xts_decrypt(cipher_blocks)

    print("\n--- Decryption Result ---")
    print("Ciphertext (decimal) :", format_blocks_decimal(cipher_blocks))
    print("Ciphertext (hex)     :", format_blocks_hex(cipher_blocks))
    print("k1 used              :", k1)
    print("k2 used              :", k2)
    print("Plaintext            :", plaintext)

except ValueError as e:
    print(f"Invalid ciphertext format: {e}")