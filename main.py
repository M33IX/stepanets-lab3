from aes import AES_CBC
from dsa import generate_dsa_keys, generate_dsa_parameters, sign_message, verify_signature, DSAKeyPair, DSASignature
from eg import encrypt as eg_encrypt, decrypt as eg_decrypt

def combine_c1c2(c1: int, c2: int) -> str:
    return str(f"{c1} {c2}")

def split_c1c2(combined: str) -> tuple[int, int]:
    parts = combined.strip().split()
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

    encrypted_aes_key = eg_encrypt(int_aes_key, eg_public_key)

    __encrypted_key = combine_c1c2(*encrypted_aes_key)

    signature = sign_message(__encrypted_key, dsa_keypair)

    return (__encrypted_key, iv, encrypted_message, signature)

def decrypt(
        data: tuple[str, bytes, bytes, DSASignature | None],
        elgamal_private_key: int,
        elgamal_public_key: tuple[int, int, int],
        dsa_key_pair: DSAKeyPair
    ) -> bytes:
    __encrypted_aes_key, iv, encrypted_message, signature = data

    if not verify_signature(__encrypted_aes_key, signature, dsa_key_pair): #type:ignore
        raise ValueError("Подпись не верна")
    
    __dectypted_aes_key = split_c1c2(__encrypted_aes_key)
    __int_aes_key = eg_decrypt(__dectypted_aes_key, elgamal_private_key, elgamal_public_key)
    aes_key = __int_aes_key.to_bytes(length=16)

    aes = AES_CBC(aes_key)

    return aes.decrypt(iv, encrypted_message)


if __name__ == "__main__":
    elgamal_public_key = (2, 784637716923335095479473677900958302012794430558004314147, 512611549290850354559007451159799160374583379513555087922)
    elgamal_private_key = 740087272825788791299402804606531437541517101921654580582

    dsa_p, dsa_q, dsa_g = generate_dsa_parameters()
    dsa_key_pair = generate_dsa_keys(dsa_p, dsa_q, dsa_g)

    aes_key = b'Test16bytekey123'
    plaintext = b'SECRET MESSAGE'

    encrypted_result = encrypt(plaintext, aes_key, elgamal_public_key, dsa_key_pair)
    decrypted_result = decrypt(encrypted_result, elgamal_private_key, elgamal_public_key, dsa_key_pair)

    print("Оригинальное сообщение:", plaintext)
    print("Расшифрованное сообщение:", decrypted_result)
