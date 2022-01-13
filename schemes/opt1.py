from __future__ import annotations

import json
import math
import os
from datetime import datetime

from Cryptodome.PublicKey import DSA
from Cryptodome.Random import random

from .common import PARAMS_PATH, Lfunction, chinese_remainder
from .config import CHEAT, DEFAULT_KEYSIZE, POWER, USE_PARALLEL

if USE_PARALLEL:
    import multiprocessing

    from joblib import Parallel, delayed

    NUM_CORES = multiprocessing.cpu_count()


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
            # Generate DSA g, p, q parameters twice
            dsa1 = DSA.generate(n_length // 2)
            dsa2 = DSA.generate(n_length // 2)

            # Check if g to the power of it's order*p
            # is also generator in Z*_p*p
            assert pow(dsa1.g, dsa1.q * dsa1.p, dsa1.p * dsa1.p) == 1
            assert pow(dsa2.g, dsa2.q * dsa2.p, dsa2.p * dsa2.p) == 1

            p1 = dsa1.p
            p2 = dsa2.p
            n = p1 * p2  # the same as n = p * q
            nsquared = n * n
            lambd = math.lcm(p1 - 1, p2 - 1)

            # Find g of order alpha*n in Z*_nsquared using DCA parameters:
            # 1) find g of order q1*q2*p1*p2 in Z*_p1*p1*p2*p2 using CRT:
            #       g = g1 (mod p1*p1)
            #       g = g2 (mod p2*p2)
            # explaned here: https://math.stackexchange.com/questions/4348052
            # 2) the same g has order q1*q2*n in Z*_nsquared
            # 3) alpha = q1*q2
            g = chinese_remainder([p1 * p1, p2 * p2], [dsa1.g, dsa2.g])
            alpha = dsa1.q * dsa2.q

            # Check if new alpha is divisor of lambd
            assert lambd % alpha == 0

            # Check if g is the order of alpha*n in Z*_nsquared
            assert pow(g, alpha * n, nsquared) == 1

            self.public = Public(n, g, nsquared)
            self.private = Private(p1, p2, alpha)

            # Precompute g^m to speed up encryption
            self.precomputed_gm = {}
            self.precompute_gm(g, nsquared)

            self.saveJson()

    @staticmethod
    def constructFromJsonFile(file_name: str) -> PaillierScheme:
        ps = PaillierScheme(generate=False)
        if file_name is not None:
            with open(
                os.path.join(PARAMS_PATH, file_name), encoding="ISO-8859-2"
            ) as file:
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
            "opt1-"
            + str(datetime.now()).replace(" ", "_").replace(":", ".")
            + ".json"
        )

        if not os.path.exists(PARAMS_PATH):
            os.mkdir(PARAMS_PATH)

        with open(
            os.path.join(PARAMS_PATH, self.file_name),
            "w",
            encoding="ISO-8859-2",
        ) as file:
            json.dump(params, file)

    @staticmethod
    def compute_gm(g: int, power: int, i: int, j: int, nsquared: int) -> int:
        value = pow(g, ((power ** i) * j), nsquared)
        if j % 1000 == 0:
            print(f"Precomputed g^m for i = {i} and j = {j}")
        return value

    def precompute_gm(self, g: int, nsquared: int) -> None:
        for i in [0, 1]:
            self.precomputed_gm[str(i)] = {}

            if USE_PARALLEL:
                result = Parallel(n_jobs=NUM_CORES)(
                    delayed(self.compute_gm)(g, POWER, i, j, nsquared)
                    for j in range(POWER)
                )

                if isinstance(result, list):
                    self.precomputed_gm[str(i)] = {
                        str(index): value for index, value in enumerate(result)
                    }
                else:
                    raise TypeError("Result should be list of ints!")
            else:
                for j in range(POWER):
                    self.precomputed_gm[str(i)][str(i)] = self.compute_gm(
                        g, POWER, i, j, nsquared
                    )

    def encrypt(self, message: int) -> int:
        if message >= self.public.n:
            raise ValueError("Message must be less than n")

        if message.bit_length() > int(math.log2(POWER)) * 2:
            raise ValueError(
                f"Message can't be more than {int(math.log2(POWER)) * 2} bits"
                " long"
            )

        # Split message into two 16-bits numbers
        j0 = (message // (POWER ** 0)) % POWER
        j1 = (message // (POWER ** 1)) % POWER

        gm = (
            self.precomputed_gm["0"][str(j0)]
            * self.precomputed_gm["1"][str(j1)]
        ) % self.public.nsquared

        # Generate r using generator g
        if CHEAT:
            r = random.randint(1, self.private.alpha - 1)
        else:
            r = pow(
                self.public.g,
                random.randint(1, self.public.n),
                self.public.n,
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

    def add_two_ciphertexts(self, ct1: int, ct2: int):
        return (ct1 * ct2) % self.public.nsquared
