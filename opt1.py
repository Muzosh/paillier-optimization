import json
import math
import pickle
from functools import reduce

from Cryptodome.Hash import SHA256
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
    def __init__(self, generate=True, n_length=DEFAULT_KEYSIZE) -> None:
        if generate:
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
            assert pow(g, alpha * n, nsquared) == 1

            self.public = Public(n, g, nsquared)
            self.private = Private(p, q, alpha)
            self.precomputed_gm = {}

            self.precompute_gm(g, nsquared)
            self.saveJson()

    @staticmethod
    def constructFromJsonFile(file_name):
        ps = PaillierScheme(generate=False)
        if file_name is not None:
            with open("params/" + file_name, encoding="ISO-8859-1") as file:
                data = json.load(file)
                public = data["public"]
                private = data["private"]

                ps.public = Public(
                    public["n"], public["g"], public["nsquared"]
                )
                ps.private = Private(
                    private["p"], private["q"], private["alpha"]
                )

                ps.precomputed_gm = data["precomputed_gm"]
                return ps
        else:
            raise AttributeError("File not found")

    def saveJson(self):
        params = {
            "opt": 1,
            "public": self.public.__dict__,
            "private": self.private.__dict__,
            "precomputed_gm": self.precomputed_gm,
        }

        self.file_name = (
            "opt1-"
            + str(
                int.from_bytes(
                    SHA256.new(data=pickle.dumps(self)).digest(),
                    byteorder="big",
                    signed=False,
                )
            )
            + ".json"
        )

        with open(
            "params/" + self.file_name, "w", encoding="ISO-8859-1"
        ) as file:
            json.dump(params, file)

    def precompute_gm(self, g, nsquared):
        x = 2 ** 16
        self.precomputed_gm = {}
        for i in [0, 1]:
            self.precomputed_gm[i] = {}
            for j in range(x):
                value = pow(g, ((x ** i) * j), nsquared)
                self.precomputed_gm[i][j] = value
                print(f"Precomputed for i = {i} and j = {j}")

    def encrypt(self, message):
        if message >= self.public.n:
            raise ValueError("Message must be less than n")

        x = 2 ** 16

        j0 = (message // (x ** 0)) % x
        j1 = (message // (x ** 1)) % x

        gm = (
            self.precomputed_gm["1"][str(j1)]
            * self.precomputed_gm["0"][str(j0)]
        ) % self.public.nsquared

        while True:
            r = random.randint(1, self.public.n)
            if math.gcd(r, self.public.n) == 1:
                break

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
    ps = PaillierScheme.constructFromJsonFile(
        "opt1-65882260747573595674415330539362164"
        "203477063818498049391976814605010170390900.json"
    )

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
