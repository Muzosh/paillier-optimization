import math
from functools import reduce

from Cryptodome.PublicKey import DSA
from Cryptodome.Random import random

DEFAULT_KEYSIZE = 2048


# Paillier's L-function
def Lfunction(u: int, n: int) -> int:
    return (u - 1) // n


# Chinese remainder theorem from
# https://medium.com/analytics-vidhya/chinese-remainder-theorem-using-python-25f051e391fc
def chinese_remainder(m: list, a: list) -> int:
    total = 0
    prod = reduce(lambda acc, b: acc * b, m)
    for n_i, a_i in zip(m, a):
        p = prod // n_i
        total += a_i * pow(p, -1, n_i) * p
    return total % prod


class Public:
    def __init__(self, n: int, g: int, nsquared: int) -> None:
        self.n = n
        self.g = g
        self.nsquared = nsquared


class Private:
    def __init__(self, p: int, q: int, alpha: int) -> None:
        self.p = p
        self.q = q
        self.alpha = alpha


class PaillierScheme:
    def __init__(self, n_length: int = DEFAULT_KEYSIZE) -> None:
        # Generate DSA g, p, q parameters twice
        dsa1 = DSA.generate(n_length // 2)
        dsa2 = DSA.generate(n_length // 2)

        # Check if g to the power of it's order*p is also generator in Z*_p*p
        assert pow(dsa1.g, dsa1.q * dsa1.p, dsa1.p * dsa1.p) == 1
        assert pow(dsa2.g, dsa2.q * dsa2.p, dsa2.p * dsa2.p) == 1

        p1 = dsa1.p
        p2 = dsa2.p
        n = p1 * p2  # the same as n = p * q
        nsquared = n * n
        gamma = math.lcm(p1 - 1, p2 - 1)

        # Find g of order alpha*n in Z*_nsquared using DCA parameters:
        # 1) find g of order q1*q2*p1*p2 in Z*_p1*p1*p2*p2 using CRT:
        #       g = g1 (mod p1*p1)
        #       g = g2 (mod p2*p2)
        # explaned here: https://math.stackexchange.com/questions/4348052
        # 2) the same g has order q1*q2*n in Z*_nsquared
        # 3) alpha = q1*q2
        g = chinese_remainder([p1 * p1, p2 * p2], [dsa1.g, dsa2.g])
        alpha = dsa1.q * dsa2.q

        # Check if new alpha is divisor of gamma
        assert gamma % alpha == 0
            
        # Check if g is the order of alpha*n in Z*_nsquared
        assert pow(g, alpha * n, nsquared) == 1

        self.public = Public(n, g, nsquared)
        self.private = Private(p1, p2, alpha)

    def encrypt(self, message: int) -> int:
        if message >= self.public.n:
            raise ValueError("Message must be less than n")

        # Generate r using generator g
        r = pow(
            self.public.g,
            random.randint(1, self.public.n),
            self.public.nsquared,
        )

        # Generate r as random element and check if they belong to Z*_n
        # while True:
        #     r = random.randint(1, self.public.n)
        #     if math.gcd(r, self.public.n) == 1:
        #         break

        gm = pow(self.public.g, message, self.public.nsquared)

        gnr = pow(
            pow(self.public.g, self.public.n, self.public.nsquared),
            r,
            self.public.nsquared,
        )

        ciphertext = (gm * gnr) % self.public.nsquared

        return ciphertext

    def decrypt(self, ciphertext: int) -> int:
        if ciphertext >= self.public.nsquared:
            raise ValueError("Ciphertext must be less than nsquared")

        numerator = Lfunction(
            pow(ciphertext, self.private.alpha, self.public.nsquared),
            self.public.n,
        )
        denominator = Lfunction(
            pow(self.public.g, self.private.alpha, self.public.nsquared),
            self.public.n,
        )

        # numerator/denominator in modular arithmetic = find inverse
        message = (
            numerator * pow(denominator, -1, self.public.n) % self.public.n
        )

        return message

    def add_two_ciphertexts(self, ct1: int, ct2: int) -> int:
        return (ct1 * ct2) % ps.public.nsquared


if __name__ == "__main__":
    ps = PaillierScheme()

    m1 = random.getrandbits(32)
    m2 = random.getrandbits(32)

    ct1 = ps.encrypt(m1)
    ct2 = ps.encrypt(m2)

    pt1 = ps.decrypt(ct1)
    pt2 = ps.decrypt(ct2)

    pt3 = ps.decrypt(ps.add_two_ciphertexts(ct1, ct2))

    assert pt1 == m1
    assert pt2 == m2
    assert pt1 + pt2 == pt3

    print("Finished successfully")
