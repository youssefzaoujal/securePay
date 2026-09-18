from tokenization.crypto import encrypt_card, decrypt_token

print("1. Chiffrement d'une carte...")
result = encrypt_card("4111111111111111", "12/25", "123")
print(f"   PAN chiffre: {result['encrypted_pan'][:50]}...")

print("2. Dechiffrement...")
decrypted = decrypt_token(result)
print(f"   PAN original: {decrypted['card_number']}")
print(f"   Expiry: {decrypted['card_expiry']}")
print(f"   CVV: {decrypted['card_cvv']}")

print("3. Verification securite...")
pan_in_result = "4111111111111111" in str(result)
print(f"   PAN en clair dans le resultat chiffre: {pan_in_result} (doit etre False)")
print()
print("TOURNE OK !")
