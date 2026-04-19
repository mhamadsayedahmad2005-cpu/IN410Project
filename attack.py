from xts import k1, k2, xts_encrypt, xts_decrypt, parse_ciphertext, format_blocks_decimal, format_blocks_hex

print("Choose mode:")
print("1. Encrypt plaintext")
print("2. Decrypt ciphertext")
choice = input("Enter 1 or 2: ").strip()

if choice == "1":
    plaintext = input("Enter plaintext: ")
    cipher = xts_encrypt(plaintext)

    print("\n--- Encryption Result ---")
    print("Plaintext            :", plaintext)
    print("Ciphertext (decimal) :", format_blocks_decimal(cipher))
    print("Ciphertext (hex)     :", format_blocks_hex(cipher))
    print("k1 used              :", k1)
    print("k2 used              :", k2)

    recovered = xts_decrypt(cipher)
    print("Decrypted check      :", recovered)

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
        plaintext = xts_decrypt(cipher_blocks)

        print("\n--- Decryption Result ---")
        print("Ciphertext (decimal) :", format_blocks_decimal(cipher_blocks))
        print("Ciphertext (hex)     :", format_blocks_hex(cipher_blocks))
        print("k1 used              :", k1)
        print("k2 used              :", k2)
        print("Plaintext            :", plaintext)

    except ValueError as e:
        print(f"Invalid ciphertext format: {e}")

else:
    print("Invalid choice.")