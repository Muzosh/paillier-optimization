from __future__ import annotations

import json
import math
import os
from datetime import datetime
from functools import reduce

from Cryptodome.PublicKey import DSA
from Cryptodome.Random import random

DEFAULT_KEYSIZE = 2048
USE_PARALLEL = True

if USE_PARALLEL:
    import multiprocessing

    from joblib import Parallel, delayed

    NUM_CORES = multiprocessing.cpu_count()


def Lfunction(u: int, n: int) -> int:
    return (u - 1) // n


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
    def __init__(
        self, generate: bool = True, n_length: int = DEFAULT_KEYSIZE
    ) -> None:
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
    def constructFromJsonFile(file_name: str) -> PaillierScheme:
        ps = PaillierScheme(generate=False)
        if file_name is not None:
            with open("params/" + file_name, encoding="ISO-8859-2") as file:
                data = json.load(file)
                public = data["public"]
                private = data["private"]

                ps.public = Public(
                    public["n"], public["g"], public["nsquared"]
                )
                ps.private = Private(
                    private["p"], private["q"], private["alpha"]
                )

                if "precomputed_gm" not in data:
                    raise ValueError("precomputed_gm is missing in the data")

                ps.precomputed_gm = data["precomputed_gm"]
                return ps
        else:
            raise AttributeError("File not found")

    def saveJson(self) -> None:
        params = {
            "opt": 1,
            "public": self.public.__dict__,
            "private": self.private.__dict__,
            "precomputed_gm": self.precomputed_gm,
        }

        self.file_name = (
            "opt1-" + str(datetime.now()).replace(" ", "_") + ".json"
        )

        if not os.path.exists("params"):
            os.mkdir("params")

        with open(
            "params/" + self.file_name, "w", encoding="ISO-8859-2"
        ) as file:
            json.dump(params, file)

    @staticmethod
    def compute_gm(g: int, x: int, i: int, j: int, nsquared: int) -> int:
        value = pow(g, ((x ** i) * j), nsquared)
        if j % 1000 == 0:
            print(f"Precomputed g^m for i = {i} and j = {j}")
        return value

    def precompute_gm(self, g: int, nsquared: int) -> None:
        x = 2 ** 16
        self.precomputed_gm = {}

        for i in [0, 1]:
            self.precomputed_gm[str(i)] = {}

            if USE_PARALLEL:
                result = Parallel(n_jobs=NUM_CORES)(
                    delayed(self.compute_gm)(g, x, i, j, nsquared)
                    for j in range(x)
                )
                if isinstance(result, list):
                    self.precomputed_gm[str(i)] = {
                        str(index): value for index, value in enumerate(result)
                    }
                else:
                    raise TypeError("Result should be list of ints!")
            else:
                for j in range(x):
                    self.precomputed_gm[str(i)][str(i)] = self.compute_gm(
                        g, x, i, j, nsquared
                    )

    def encrypt(self, message: int) -> int:
        if message >= self.public.n:
            raise ValueError("Message must be less than n")

        if message.bit_length() > 32:
            raise ValueError("Message can't be more than 32 bits long")

        x = 2 ** 16

        j0 = (message // (x ** 0)) % x
        j1 = (message // (x ** 1)) % x

        gm = (
            self.precomputed_gm["1"][str(j1)]
            * self.precomputed_gm["0"][str(j0)]
        ) % self.public.nsquared

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

    def decrypt(self, ciphertext: int) -> int:
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

    def add_two_ciphertexts(self, ct1: int, ct2: int):
        return (ct1 * ct2) % ps.public.nsquared


if __name__ == "__main__":
    # ps = PaillierScheme.constructFromJsonFile(
    #     "opt1-2022-01-06_22:16:03.993283.json"
    # )
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
