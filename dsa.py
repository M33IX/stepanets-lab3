import random
from typing import Tuple, Optional

class DSAKeyPair:
    def __init__(self, p: int, q: int, g: int, private_key: int):
        self.p = p
        self.q = q
        self.g = g
        self.private_key = private_key
        self.public_key = pow(g, private_key, p)

class DSASignature:
    def __init__(self, r: int, s: int):
        self.r = r
        self.s = s

def is_prime(n: int, k: int = 5) -> bool:
    """Проверка числа на простоту с использованием теста Миллера-Рабина."""
    if n <= 1:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randint(2, n-2)
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue
        for __ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

def generate_prime(bits: int) -> int:
    """Генерация простого числа заданной битности."""
    while True:
        num = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if is_prime(num):
            return num

def mod_inverse(a: int, m: int) -> Optional[int]:
    """Нахождение обратного элемента по модулю m."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        return None
    return x % m

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Расширенный алгоритм Евклида."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def simple_hash(message: str) -> int:
    """Упрощенная хэш-функция (для демонстрации)."""
    return sum(ord(c) for c in message) % (2**160)

def generate_dsa_parameters() -> Tuple[int, int, int]:
    """Генерация параметров p, q, g для DSA."""
    # Генерация q (160 бит)
    q = generate_prime(160)
    
    # Генерация p (1024 бита), где p-1 делится на q
    while True:
        k = random.getrandbits(864)
        p = q * k + 1
        if is_prime(p) and p.bit_length() == 1024:
            break
    
    # Поиск генератора g
    h = random.randint(2, p-2)
    g = pow(h, (p-1) // q, p)
    while g == 1:
        h = random.randint(2, p-2)
        g = pow(h, (p-1) // q, p)
    
    return p, q, g

def generate_dsa_keys(p: int, q: int, g: int) -> DSAKeyPair:
    """Генерация пары ключей для DSA."""
    x = random.randint(1, q-1)
    return DSAKeyPair(p, q, g, x)

def sign_message(message: str, key_pair: DSAKeyPair) -> Optional[DSASignature]:
    """Подпись сообщения по алгоритму DSA."""
    p, q, g, x = key_pair.p, key_pair.q, key_pair.g, key_pair.private_key
    h = simple_hash(message)
    
    while True:
        k = random.randint(1, q-1)
        r = pow(g, k, p) % q
        if r == 0:
            continue
        k_inv = mod_inverse(k, q)
        if k_inv is None:
            continue
        s = (k_inv * (h + x * r)) % q
        if s == 0:
            continue
        return DSASignature(r, s)

def verify_signature(message: str, signature: DSASignature, key_pair: DSAKeyPair) -> bool:
    """Проверка подписи DSA."""
    p, q, g, y = key_pair.p, key_pair.q, key_pair.g, key_pair.public_key
    r, s = signature.r, signature.s
    
    if not (0 < r < q and 0 < s < q):
        return False
    
    w = mod_inverse(s, q)
    if w is None:
        return False
    
    h = simple_hash(message)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p)) % p % q
    
    return v == r

# Пример использования
if __name__ == "__main__":
    # Генерация параметров
    p, q, g = generate_dsa_parameters()
    
    # Генерация ключей
    key_pair = generate_dsa_keys(p, q, g)
    message = "Hello, DSA!"
    
    # Подпись сообщения
    signature = sign_message(message, key_pair)
    if signature is None:
        print("Ошибка при создании подписи!")
        exit()
    
    # Проверка подписи
    is_valid = verify_signature(message, signature, key_pair)
    print(f"Подпись {'верна' if is_valid else 'неверна'}!")
    
    # Проверка с измененным сообщением
    is_valid_fake = verify_signature("Fake message", signature, key_pair)
    print(f"Подпись для фейкового сообщения {'верна' if is_valid_fake else 'неверна'}!")