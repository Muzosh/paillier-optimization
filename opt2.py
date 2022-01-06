import json
import math
from datetime import datetime
from functools import reduce
from operator import mul

from Cryptodome.PublicKey import DSA
from Cryptodome.Random import random

DEFAULT_KEYSIZE = 2048
USE_PARALLEL = True

if USE_PARALLEL:
    import multiprocessing

    from joblib import Parallel, delayed

    NUM_CORES = multiprocessing.cpu_count()


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
            gamma = abs((p-1)*(q-1)) // math.gcd((p-1), (q-1))

            g = chinese_remainder([p * p, q * q], [dsa1.g, dsa2.g])
            alpha = dsa1.q * dsa2.q

            assert gamma % alpha == 0
            assert pow(g, alpha * n, nsquared) == 1

            self.public = Public(n, g, nsquared)
            self.private = Private(p, q, alpha)
            self.precomputed_gnr = []

            self.precompute_gnr(g, n, nsquared)
            self.saveJson()

    @staticmethod
    def constructFromJsonFile(file_name):
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

                ps.precomputed_gnr = data["precomputed_gnr"]
                return ps
        else:
            raise AttributeError("File not found")

    def saveJson(self):
        params = {
            "opt": 2,
            "public": self.public.__dict__,
            "private": self.private.__dict__,
            "precomputed_gnr": self.precomputed_gnr,
        }

        self.file_name = (
            "opt2-" + str(datetime.now()).replace(" ", "_") + ".json"
        )

        with open(
            "params/" + self.file_name, "w", encoding="ISO-8859-2"
        ) as file:
            json.dump(params, file)

    @staticmethod
    def compute_gnr(g, n, nsquared, gn, i):
        # generate r using generator
        r = pow(g, random.randint(1, n), nsquared)

        # generate r as random element and check if they belong to Z*_n
        # while True:
        #     r = random.randint(1, n)
        #     if math.gcd(r, n) == 1:
        #         break

        gnr = pow(gn, r, nsquared)
        if i % 1000 == 0:
            print(f"Precomputed for i = {i}")
        return gnr

    def precompute_gnr(self, g: int, n: int, nsquared: int):
        x = 2 ** 16
        gn = pow(g, n, nsquared)

        self.precomputed_gnr = []
        if USE_PARALLEL:
            result = Parallel(n_jobs=NUM_CORES)(
                delayed(self.compute_gnr)(g, n, nsquared, gn, i)
                for i in range(x)
            )
            if isinstance(result, list):
                self.precomputed_gnr.extend(result)
            else:
                raise TypeError("Result should be list of ints!")
        else:
            for i in range(x):
                self.precomputed_gnr.append(
                    self.compute_gnr(g, n, nsquared, gn, i)
                )

    def encrypt(self, message):
        if message >= self.public.n:
            raise ValueError("Message must be less than n")

        gm = (
            pow(self.public.g, message, self.public.nsquared)
            % self.public.nsquared
        )

        gnr = (
            reduce(mul, random.sample(self.precomputed_gnr, 8), 1)
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
    # ps = PaillierScheme.constructFromJsonFile(
    #     "opt2-1050062191477719247145298894371156888"
    #     "41060793516462453144933171250246011525005.json"
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
