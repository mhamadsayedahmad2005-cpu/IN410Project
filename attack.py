from xts import xts_decrypt, parse_ciphertext

def brute_force_xts(cipher_blocks, known_word=None):
    print("\n--- Brute Force Attack ---")

    for K1 in range(256):
        for K2 in range(256):
            try:
                plaintext = xts_decrypt(cipher_blocks, K1, K2)

            
                if known_word:
                    if known_word.lower() in plaintext.lower():
                        print("\nKey found!")
                        print("K1 =", K1)
                        print("K2 =", K2)
                        print("Plaintext =", plaintext)
                        return

                # Otherwise show readable outputs
                else:
                    if plaintext.isprintable() and len(plaintext.strip()) > 0:
                        print(f"K1={K1}, K2={K2} -> {plaintext}")

            except:
                pass

    print("No key found.")


# Run attack

if __name__ == "__main__":
    cipher_input = input(
        "Enter ciphertext blocks (decimal or hex):\n> "
    )

    known_word = input(
        "Enter known word (optional, press Enter to skip): "
    ).strip()

    if known_word == "":
        known_word = None

    try:
        cipher_blocks = parse_ciphertext(cipher_input)
        brute_force_xts(cipher_blocks, known_word)

    except ValueError as e:
        print("Error:", e)