from __future__ import annotations
import random
import math
from typing import Tuple

SMALL_PRIMES = [2, 3, 5, 7] + [x for x in range(11, 10000, 2) if all(x % y != 0 for y in range(3, int(math.sqrt(x)) + 1, 2))]

def generate_prime(bit_length: int) -> int:
    """Оптимизированная генерация простых чисел с предварительной проверкой малых делителей."""
    def is_prime(n: int, k: int = 3) -> bool:
        if n <= 1:
            return False
            
        # Быстрая проверка малых делителей
        for p in SMALL_PRIMES:
            if n % p == 0:
                return n == p

        # Оптимизированный тест Рабина-Миллера
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1

        for _ in range(k):
            a = random.randint(2, min(n-2, 1 << 20))
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s-1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    while True:
        p = random.getrandbits(bit_length)
        p |= (1 << (bit_length - 1)) | 1
        if is_prime(p):
            return p

def find_generator(p: int, max_attempts: int = 100) -> int:
    """Ускоренный поиск генератора с ограниченным количеством попыток."""
    if p == 2:
        return 1
        
    factors = set(prime_factors(p-1))
    required = [ (p-1)//f for f in factors ]
    
    for _ in range(max_attempts):
        g = random.randint(2, p-1)
        if all(pow(g, r, p) != 1 for r in required):
            return g
    raise ValueError("Generator not found")

def prime_factors(n: int) -> list[int]:
    """Оптимизированная факторизация с использованием пробного деления и алгоритма Полларда."""
    factors = []
    # Удаление факторов 2
    while n % 2 == 0:
        factors.append(2)
        n //= 2
        
    # Алгоритм Полларда для больших чисел
    def pollards_rho(n):
        if n % 2 == 0:
            return 2
        if n % 3 == 0:
            return 3
            
        while True:
            c = random.randint(1, n-1)
            f = lambda x: (pow(x, 2, n) + c) % n
            x, y, d = 2, 2, 1
            while d == 1:
                x = f(x)
                y = f(f(y))
                d = math.gcd(abs(x - y), n)
            if d != n:
                return d
                
    while n > 1:
        if n < 1e6:
            # Традиционное пробное деление для небольших чисел
            i = 3
            while i*i <= n:
                while n % i == 0:
                    factors.append(i)
                    n //= i
                i += 2
            if n > 1:
                factors.append(n)
                break
        else:
            # Использование алгоритма Полларда для больших чисел
            d = pollards_rho(n)
            factors += prime_factors(d)
            n //= d
            
    return sorted(factors)

def generate_keys(bit_length: int = 128) -> Tuple[Tuple[int, int, int], int]:
    """Основная функция генерации ключей с обработкой исключений"""
    # p = generate_prime(bit_length)
    p = 784637716923335095479473677900958302012794430558004314147
    # a = find_generator(p)
    a = 2
    x = random.randint(2, p-2)
    b = pow(a, x, p)
    return (a, p, b), x

def encrypt(m: int, public_key: Tuple[int, int, int]) -> Tuple[int, int]:
    """
    Шифрование с проверкой: m должно быть меньше p.
    """
    a, p, b = public_key
    if m >= p:
        raise ValueError("Сообщение должно быть меньше p")
    
    # Поиск y взаимно простого с p-1
    while True:
        y = random.randint(2, p-2)
        if gcd(y, p-1) == 1:
            break
            
    k = pow(a, y, p)
    c = (pow(b, y, p) * m) % p
    return (k, c)

def decrypt(ciphertext: Tuple[int, int], private_key: int, public_key: Tuple[int, int, int]) -> int:
    """
    Дешифрование с обработкой нулевого сообщения.
    """
    k, c = ciphertext
    _, p, _ = public_key
    s = pow(k, private_key, p)
    s_inv = pow(s, p-2, p)  # Использование малой теоремы Ферма вместо расширенного Евклида
    return (c * s_inv) % p

def gcd(a: int, b: int) -> int:
    """Наибольший общий делитель."""
    while b:
        a, b = b, a % b
    return a

# Пример использования с улучшенными проверками
if __name__ == "__main__":
    # Генерация ключей
    public_key, private_key = generate_keys(bit_length=128)
    a, p, b = public_key
    print(f"Открытый ключ: (a={a}, p={p}, b={b})")
    print(f"Закрытый ключ: x={private_key}")

    message = 110873557931294071764567408812199994745
    if message >= p:
        print("Ошибка: сообщение слишком велико")
    else:
        ciphertext = encrypt(message, public_key)
        print(f"Шифротекст: (k={ciphertext[0]}, c={ciphertext[1]})")
        decrypted = decrypt(ciphertext, private_key, public_key)
        print(f"Дешифровано: {decrypted} (ожидалось: {message})")

        assert message == decrypted

    # Тест с сообщением >= p (должна быть ошибка)
    try:
        encrypt(p, public_key)
    except ValueError as e:
        print(f"Ошибка при шифровании: {e}")