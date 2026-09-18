"""Tests unitaires — AES-256-GCM, CVV jamais persisté (PCI-DSS Req 3.2)."""

from tokenization.crypto import decrypt_token, encrypt_card


class TestTokenizationCrypto:
    def test_encrypt_returns_dict_with_encrypted_fields(self):
        result = encrypt_card("4111111111111111", "12/25", "123")
        assert "encrypted_pan" in result
        assert "encrypted_expiry" in result
        assert result["cvv_stored"] is False
        assert result["algorithm"] == "AES-256-GCM"
        assert "encrypted_cvv" not in result

    def test_decrypt_returns_original_pan_and_expiry(self):
        encrypted = encrypt_card("4111111111111111", "12/25", "123")
        decrypted = decrypt_token(encrypted)
        assert decrypted["card_number"] == "4111111111111111"
        assert decrypted["card_expiry"] == "12/25"
        assert decrypted["card_cvv"] is None

    def test_different_encryptions_produce_different_ciphertexts(self):
        enc1 = encrypt_card("4111111111111111", "12/25", "123")
        enc2 = encrypt_card("4111111111111111", "12/25", "123")
        assert enc1["encrypted_pan"] != enc2["encrypted_pan"]

    def test_pan_never_stored_in_plaintext(self):
        result = encrypt_card("4111111111111111", "12/25", "123")
        assert "4111111111111111" not in str(result)

    def test_cvv_never_in_ciphertext_payload(self):
        result = encrypt_card("4111111111111111", "12/25", "999")
        assert "encrypted_cvv" not in result
        assert result["cvv_stored"] is False
