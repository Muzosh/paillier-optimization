from Cryptodome.Random import random
from Cryptodome.Util.number import getStrongPrime
from sympy.ntheory.factor_ import totient
import math

DEFAULT_KEYSIZE = 2048


def Lfunction(u, n):
    return (u - 1) // n


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


class PaillierScheme1:
    def __init__(self, n_length=DEFAULT_KEYSIZE) -> None:
        p = q = n = 0
        n_len = 0
        while n_len != n_length:
            p = getStrongPrime(n_length // 2)
            q = p
            while q == p:
                q = getStrongPrime(n_length // 2)
            n = p * q
            n_len = n.bit_length()

        nsquared = n * n
        gamma = math.lcm(p - 1, q - 1)
        # TODO: generation of alpha - DSA twice?
        alpha = gamma

        # TODO: the order of g is alpha*n
        g = 0
        for i in range(2, nsquared):
            if (
                math.gcd(i, nsquared) == 1
                and math.gcd(Lfunction(pow(i, alpha, nsquared), n), n) == 1
            ):
                g = i
                break

        self.public = Public(n, g, nsquared)
        self.private = Private(p, q, alpha)

    def encrypt(self, message):
        if message >= self.public.n:
            raise ValueError("Message must be less than n")

        while True:
            r = random.randint(1, self.public.n)
            if math.gcd(r, self.public.n) == 1:
                break

        ciphertext = (
            pow(self.public.g, message, self.public.nsquared)
            * pow(
                pow(self.public.g, self.public.n, self.public.nsquared),
                r,
                self.public.nsquared,
            )
            % self.public.nsquared
        )

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
    ps = PaillierScheme1()
    ct1 = ps.encrypt(3)
    ct2 = ps.encrypt(11)

    pt1 = ps.decrypt(ct1)
    pt2 = ps.decrypt(ct2)

    pt3 = ps.decrypt(ps.add_two_ciphertexts(ct1, ct2))

    pass
