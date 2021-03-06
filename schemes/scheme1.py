import math

from Cryptodome.Random import random
from Cryptodome.Util.number import getStrongPrime

from .common import Lfunction
from .config import DEFAULT_KEYSIZE


class Public:
    def __init__(self, n: int, g: int, nsquared: int) -> None:
        self.n = n
        self.g = g
        self.nsquared = nsquared


class Private:
    def __init__(self, p: int, q: int, lambd: int) -> None:
        self.p = p
        self.q = q
        self.lambd = lambd


class PaillierScheme:
    def __init__(self, n_length: int = DEFAULT_KEYSIZE) -> None:
        p = q = n = 0
        n_len = 0

        # Generate primes p and q until their product is right length
        while n_len != n_length:
            p = getStrongPrime(n_length // 2)
            q = p
            while q == p:
                q = getStrongPrime(n_length // 2)
            n = p * q
            n_len = n.bit_length()

        nsquared = n * n
        lambd = math.lcm(p - 1, q - 1)

        # Generate small (performance reasons) g such that g is element of
        # Z*_nsquared and also is order of n (can be checked effectively)
        g = 0
        for i in range(2, nsquared):
            if (
                math.gcd(i, nsquared) == 1
                and math.gcd(Lfunction(pow(i, lambd, nsquared), n), n) == 1
            ):
                g = i
                break

        self.public = Public(n, g, nsquared)
        self.private = Private(p, q, lambd)

    def encrypt(self, message: int) -> int:
        if message >= self.public.n:
            raise ValueError("Message must be less than n")

        r = pow(
            self.public.g,
            random.randint(1, self.public.n),
            self.public.n,
        )

        gm = pow(self.public.g, message, self.public.nsquared)
        rn = pow(r, self.public.n, self.public.nsquared)

        ciphertext = (gm * rn) % self.public.nsquared

        return ciphertext

    def decrypt(self, ciphertext: int) -> int:
        if ciphertext >= self.public.nsquared:
            raise ValueError("Ciphertext must be less than nsquared")

        numerator = Lfunction(
            pow(ciphertext, self.private.lambd, self.public.nsquared),
            self.public.n,
        )
        denominator = Lfunction(
            pow(self.public.g, self.private.lambd, self.public.nsquared),
            self.public.n,
        )

        # numerator/denominator in modular arithmetic = find inverse
        message = (
            numerator * pow(denominator, -1, self.public.n) % self.public.n
        )

        return message

    def add_two_ciphertexts(self, ct1: int, ct2: int) -> int:
        return (ct1 * ct2) % self.public.nsquared
