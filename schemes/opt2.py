from __future__ import annotations

import json
import math
import os
from datetime import datetime
from functools import reduce
from operator import mul

from Cryptodome.PublicKey import DSA
from Cryptodome.Random import random

from .common import PARAMS_PATH, Lfunction, chinese_remainder
from .config import CHEAT, DEFAULT_KEYSIZE, NO_GNR, POWER, USE_PARALLEL

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
            # 2) the same g has order q1*q2*n in Z*_squared
            # 3) alpha = q1*q2
            g = chinese_remainder([p1 * p1, p2 * p2], [dsa1.g, dsa2.g])
            alpha = dsa1.q * dsa2.q

            # Check if new alpha is divisor of lambd
            assert lambd % alpha == 0

            # Check if g is the order of alpha*n in Z*_nsquared
            assert pow(g, alpha * n, nsquared) == 1

            self.public = Public(n, g, nsquared)
            self.private = Private(p1, p2, alpha)

            # Precompute (g^n)^r to speed up encryption
            self.precomputed_gnr = []
            self.precompute_gnr(g, n, nsquared, alpha)

            self.saveJson()

    @staticmethod
    def constructFromJsonFile(file_name: str) -> PaillierScheme:
        ps = PaillierScheme(generate=False)
        if file_name is not None:
            with open(
                os.path.join(
                    PARAMS_PATH,
                    file_name,
                ),
                encoding="ISO-8859-2",
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

                if "precomputed_gnr" not in data:
                    raise ValueError("precomputed_gnr is missing in the data")

                ps.precomputed_gnr = data["precomputed_gnr"]
                return ps
        else:
            raise AttributeError("File not found")

    def saveJson(self) -> None:
        params = {
            "opt": 2,
            "public": self.public.__dict__,
            "private": self.private.__dict__,
            "precomputed_gnr": self.precomputed_gnr,
        }

        self.file_name = (
            "opt2-"
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
    def compute_gnr(
        g: int, n: int, nsquared: int, gn: int, i: int, alpha: int
    ) -> int:
        # Generate r using generator g
        if CHEAT:
            r = random.randint(1, alpha - 1)
        else:
            r = pow(g, random.randint(1, n), n)

        gnr = pow(gn, r, nsquared)
        if i % 1000 == 0:
            print(f"Precomputed g^n^r for i = {i}")
        return gnr

    def precompute_gnr(
        self, g: int, n: int, nsquared: int, alpha: int
    ) -> None:
        gn = pow(g, n, nsquared)

        if USE_PARALLEL:
            result = Parallel(n_jobs=NUM_CORES)(
                delayed(self.compute_gnr)(g, n, nsquared, gn, i, alpha)
                for i in range(POWER)
            )

            if isinstance(result, list):
                self.precomputed_gnr.extend(result)
            else:
                raise TypeError("Result should be list of ints!")
        else:
            for i in range(POWER):
                self.precomputed_gnr.append(
                    self.compute_gnr(g, n, nsquared, gn, i, alpha)
                )

    def encrypt(self, message: int) -> int:
        if message >= self.public.n:
            raise ValueError("Message must be less than n")

        gm = pow(self.public.g, message, self.public.nsquared)

        # Get NO_GNR random precomputed (g^n)^r and
        # multiply them with each other
        gnr = (
            reduce(mul, random.sample(self.precomputed_gnr, NO_GNR), 1)
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

    def add_two_ciphertexts(self, ct1: int, ct2: int) -> int:
        return (ct1 * ct2) % self.public.nsquared
