import math
from functools import reduce

from Cryptodome.PublicKey import DSA
from Cryptodome.Random import random

DEFAULT_KEYSIZE = 2048


def Lfunction(u, n):
    return (u - 1) // n


def chinese_remainder(m, a):
    total = 0
    prod = reduce(lambda acc, b: acc * b, m)
    for n_i, a_i in zip(m, a):
        p = prod // n_i
        total += a_i * pow(p, -1, n_i) * p
    return total % prod


class Public:
    def __init__(self, n, g, nsquared) -> None:
        self.n = n
        self.g = g
        self.nsquared = nsquared


class Private:
    def __init__(self, p, q, alpha) -> None:
        self.p = p
        self.q = q
        self.alpha = alpha


class PaillierScheme:
    def __init__(self, n_length=DEFAULT_KEYSIZE) -> None:
        dsa1 = DSA.generate(n_length // 2)
        dsa2 = DSA.generate(n_length // 2)
        assert pow(dsa1.g, dsa1.q * dsa1.p, dsa1.p * dsa1.p) == 1
        assert pow(dsa2.g, dsa2.q * dsa2.p, dsa2.p * dsa2.p) == 1

        p = dsa1.p
        q = dsa2.p
        n = p * q
        nsquared = n * n
        gamma = math.lcm(p - 1, q - 1)

        g = chinese_remainder([p * p, q * q], [dsa1.g, dsa2.g])
        alpha = dsa1.q * dsa2.q

        assert gamma % alpha == 0

        self.public = Public(n, g, nsquared)
        self.private = Private(p, q, alpha)

    def encrypt(self, message):
        if message >= self.public.n:
            raise ValueError("Message must be less than n")

        # generate r using generator
        r = pow(
            self.public.g,
            random.randint(1, self.public.n),
            self.public.nsquared,
        )
        
        # generate r as random element and check if they belong to Z*_n
        # while True:
        #     r = random.randint(1, self.public.n)
        #     if math.gcd(r, self.public.n) == 1:
        #         break

        gm = (
            pow(self.public.g, message, self.public.nsquared)
            % self.public.nsquared
        )

        gnr = (
            pow(
                pow(self.public.g, self.public.n, self.public.nsquared),
                r,
                self.public.nsquared,
            )
            % self.public.nsquared
        )

        ciphertext = (gm * gnr) % self.public.nsquared

        return ciphertext

    def decrypt(self, ciphertext):
        if ciphertext >= self.public.nsquared:
            raise ValueError("Ciphertext must be less than nsquared")

        upper = Lfunction(
            pow(ciphertext, self.private.alpha, self.public.nsquared),
            self.public.n,
        )
        lower = Lfunction(
            pow(self.public.g, self.private.alpha, self.public.nsquared),
            self.public.n,
        )

        message = upper * pow(lower, -1, self.public.n) % self.public.n

        return message

    def add_two_ciphertexts(self, ct1, ct2):
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
