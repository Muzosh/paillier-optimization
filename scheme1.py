import math

from Cryptodome.Random import random
from Cryptodome.Util.number import getStrongPrime

DEFAULT_KEYSIZE = 2048


def Lfunction(u: int, n: int) -> int:
    return (u - 1) // n


class Public:
    def __init__(self, n: int, g: int, nsquared: int) -> None:
        self.n = n
        self.g = g
        self.nsquared = nsquared


class Private:
    def __init__(self, p: int, q: int, gamma: int) -> None:
        self.p = p
        self.q = q
        self.gamma = gamma


class PaillierScheme:
    def __init__(self, n_length: int = DEFAULT_KEYSIZE) -> None:
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

        g = 0
        for i in range(2, nsquared):
            if (
                math.gcd(i, nsquared) == 1
                and math.gcd(Lfunction(pow(i, gamma, nsquared), n), n) == 1
            ):
                g = i
                break

        self.public = Public(n, g, nsquared)
        self.private = Private(p, q, gamma)

    def encrypt(self, message: int) -> int:
        if message >= self.public.n:
            raise ValueError("Message must be less than n")

        if message.bit_length() > 32:
            raise ValueError("Message can't be more than 32 bits long")

        while True:
            r = random.randint(1, self.public.n)
            if math.gcd(r, self.public.n) == 1:
                break

        ciphertext = (
            pow(self.public.g, message, self.public.nsquared)
            * pow(r, self.public.n, self.public.nsquared)
            % self.public.nsquared
        )

        return ciphertext

    def decrypt(self, ciphertext: int) -> int:
        if ciphertext >= self.public.nsquared:
            raise ValueError("Ciphertext must be less than nsquared")

        upper = Lfunction(
            pow(ciphertext, self.private.gamma, self.public.nsquared),
            self.public.n,
        )
        lower = Lfunction(
            pow(self.public.g, self.private.gamma, self.public.nsquared),
            self.public.n,
        )

        message = upper * pow(lower, -1, self.public.n) % self.public.n

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
