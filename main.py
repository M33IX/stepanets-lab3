from aes import AES_CBC
from dsa import generate_dsa_keys, generate_dsa_parameters, sign_message, verify_signature, DSAKeyPair, DSASignature
from eg import generate_keys as generate_eg_keys, encrypt as eg_encrypt, decrypt as eg_decrypt

def combine_c1c2(c1: int, c2: int) -> str:
    """Объединение c1 и c2 в одну строку"""
    return str(f"{c1} {c2}")

def split_c1c2(combined: str) -> tuple[int, int]:
    """Разделение объединенной строки на c1 и c2"""
    parts = combined.strip().split()
    if len(parts) != 2:
        raise ValueError("Ожидалась строка с двумя числами, разделёнными пробелом")
    c1, c2 = map(int, parts)
    return c1, c2

def encrypt(
        plaintext: bytes, 
        aes_key: bytes, 
        eg_public_key: tuple[int, int, int], 
        dsa_keypair: DSAKeyPair
    ) -> tuple[str, bytes, bytes, DSASignature | None]:
    aes = AES_CBC(aes_key)

    iv, encrypted_message = aes.encrypt(plaintext)
    int_aes_key = int.from_bytes(aes_key)
    print(int_aes_key)

    encrypted_aes_key = eg_encrypt(int_aes_key, eg_public_key)

    combined_public_key = combine_c1c2(*encrypted_aes_key)

    signature = sign_message(combined_public_key, dsa_keypair)

    return (combined_public_key, iv, encrypted_message, signature)

def decrypt(
        data: tuple[str, bytes, bytes, DSASignature | None],
        elgamal_private_key: int,
        elgamal_public_key: tuple[int, int, int],
        dsa_key_pair: DSAKeyPair
    ) -> bytes:
    encrypted_aes_key, iv, encrypted_message, signature = data

    if not verify_signature(encrypted_aes_key, signature, dsa_key_pair): #type:ignore
        raise ValueError("Подпись не верна")
    
    restored_aes_key = split_c1c2(encrypted_aes_key)
    aes_key_int = eg_decrypt(restored_aes_key, elgamal_private_key, elgamal_public_key)
    print(aes_key_int)
    aes_key = aes_key_int.to_bytes(length=16)

    aes = AES_CBC(aes_key)

    return aes.decrypt(iv, encrypted_message)


if __name__ == "__main__":
    eg_public, eg_private = generate_eg_keys(bit_length=16)

    dsa_p, dsa_q, dsa_g = generate_dsa_parameters()
    dsa_key_pair = generate_dsa_keys(dsa_p, dsa_q, dsa_g)

    aes_key = b'Sixteen byte key'
    plaintext = b'This is a test message'

    assert int.from_bytes(aes_key).to_bytes(length=16) == aes_key

    encrypted_result = encrypt(plaintext, aes_key, eg_public, dsa_key_pair)
    decrypted_result = decrypt(encrypted_result, eg_private, eg_public, dsa_key_pair)

    print(plaintext)
    print(decrypted_result)
