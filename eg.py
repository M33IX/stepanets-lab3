import random
from typing import Tuple

def generate_prime(bit_length: int) -> int:
    """
    Генерация большого простого числа заданной битовой длины с использованием теста Рабина-Миллера.
    """
    def is_prime(n: int, k: int = 5) -> bool:
        """
        Тест Рабина-Миллера на простоту.
        """
        if n <= 1:
            return False
        if n <= 3:
            return True
        # Представление n-1 в виде (2^s * d)
        s, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            s += 1
        # Проведение k тестов
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    # Генерация числа с установкой старшего и младшего битов в 1
    while True:
        p = random.getrandbits(bit_length)
        p |= (1 << (bit_length - 1)) | 1  # Установка старшего и младшего битов
        if is_prime(p):
            return p

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Расширенный алгоритм Евклида для нахождения НОД и коэффициентов Безу.
    Возвращает (gcd, x, y), такие что ax + by = gcd(a, b).
    """
    if a == 0:
        return (b, 0, 1)
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return (gcd, y - (b // a) * x, x)

def mod_inverse(a: int, m: int) -> int:
    """
    Нахождение обратного элемента по модулю m.
    """
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Обратный элемент не существует")
    else:
        return x % m

def generate_keys(bit_length: int = 512) -> Tuple[Tuple[int, int, int], int]:
    """
    Генерация ключей для алгоритма Эль Гамаля.
    Возвращает ((a, p, b), x), где (a, p, b) — открытый ключ, x — закрытый ключ.
    """
    p = generate_prime(bit_length)
    a = find_generator(p)
    x = random.randint(2, p - 2)
    b = pow(a, x, p)
    return (a, p, b), x

def find_generator(p: int) -> int:
    """
    Поиск образующего элемента (первообразного корня) для простого p.
    """
    if p == 2:
        return 1
    # Факторизация p-1
    factors = prime_factors(p - 1)
    # Проверка для каждого числа
    for g in range(2, p):
        if all(pow(g, (p - 1) // f, p) != 1 for f in factors):
            return g
    raise ValueError("Образующий элемент не найден")

def prime_factors(n: int) -> list:
    """
    Возвращает список простых делителей числа n.
    """
    i = 2
    factors = set()
    while i * i <= n:
        if n % i:
            i += 1
        else:
            factors.add(i)
            while n % i == 0:
                n //= i
    if n > 1:
        factors.add(n)
    return list(factors)

def encrypt(m: int, public_key: Tuple[int, int, int]) -> Tuple[int, int]:
    """
    Шифрование сообщения m открытым ключом (a, p, b).
    Возвращает пару (k, c).
    """
    a, p, b = public_key
    y = random.randint(2, p - 2)
    while extended_gcd(y, p - 1)[0] != 1:  # Проверка взаимной простоты
        y = random.randint(2, p - 2)
    k = pow(a, y, p)
    c = (pow(b, y, p) * m) % p
    return (k, c)

def decrypt(ciphertext: Tuple[int, int], private_key: int, public_key: Tuple[int, int, int]) -> int:
    """
    Дешифрование пары (k, c) закрытым ключом x.
    """
    k, c = ciphertext
    a, p, b = public_key
    x = private_key
    s = pow(k, x, p)
    s_inv = mod_inverse(s, p)
    return (c * s_inv) % p

# Пример использования
if __name__ == "__main__":
    # Генерация ключей
    public_key, private_key = generate_keys(bit_length=16)  # Для примера используем короткие ключи
    print(f"Открытый ключ: (a={public_key[0]}, p={public_key[1]}, b={public_key[2]})")
    print(f"Закрытый ключ: x={private_key}")

    # Шифрование сообщения
    message = 1234567897437574757457475377377773745737783883
    ciphertext = encrypt(message, public_key)
    print(f"Шифротекст: (k={ciphertext[0]}, c={ciphertext[1]})")

    # Дешифрование
    decrypted = decrypt(ciphertext, private_key, public_key)
    assert message == decrypted
    print(f"Дешифрованное сообщение: {decrypted}")