import math

from Cryptodome.Random import random

from schemes import (
    precompute_both_scheme,
    precompute_gm_scheme,
    precompute_gnr_scheme,
    scheme1,
    scheme3,
)
from schemes.config import POWER


def testScheme1(m1, m2):
    ps = scheme1.PaillierScheme()

    ct1 = ps.encrypt(m1)
    ct2 = ps.encrypt(m2)

    pt1 = ps.decrypt(ct1)
    pt2 = ps.decrypt(ct2)

    pt3 = ps.decrypt(ps.add_two_ciphertexts(ct1, ct2))

    assert pt1 == m1
    assert pt2 == m2
    assert pt1 + pt2 == pt3


def testScheme3(m1, m2):
    ps = scheme3.PaillierScheme()

    ct1 = ps.encrypt(m1)
    ct2 = ps.encrypt(m2)

    pt1 = ps.decrypt(ct1)
    pt2 = ps.decrypt(ct2)

    pt3 = ps.decrypt(ps.add_two_ciphertexts(ct1, ct2))

    assert pt1 == m1
    assert pt2 == m2
    assert pt1 + pt2 == pt3


def testPrecomputeGm(m1, m2):
    ps = precompute_gm_scheme.PaillierScheme.constructFromJsonFile(
        "precompute_gm-2022-01-06_22:16:03.993283.json"
    )

    ct1 = ps.encrypt(m1)
    ct2 = ps.encrypt(m2)

    pt1 = ps.decrypt(ct1)
    pt2 = ps.decrypt(ct2)

    pt3 = ps.decrypt(ps.add_two_ciphertexts(ct1, ct2))

    assert pt1 == m1
    assert pt2 == m2
    assert pt1 + pt2 == pt3


def testPrecomputeGnr(m1, m2):
    ps = precompute_gnr_scheme.PaillierScheme.constructFromJsonFile(
        "precompute_both-2022-01-07_14.47.27.047353.json"
    )

    ct1 = ps.encrypt(m1)
    ct2 = ps.encrypt(m2)

    pt1 = ps.decrypt(ct1)
    pt2 = ps.decrypt(ct2)

    pt3 = ps.decrypt(ps.add_two_ciphertexts(ct1, ct2))

    assert pt1 == m1
    assert pt2 == m2
    assert pt1 + pt2 == pt3


def testPrecomputeBoth(m1, m2):
    ps = precompute_both_scheme.PaillierScheme.constructFromJsonFile(
        "precompute_both-2022-01-07_14.47.27.047353.json"
    )

    ct1 = ps.encrypt(m1)
    ct2 = ps.encrypt(m2)

    pt1 = ps.decrypt(ct1)
    pt2 = ps.decrypt(ct2)

    pt3 = ps.decrypt(ps.add_two_ciphertexts(ct1, ct2))

    assert pt1 == m1
    assert pt2 == m2
    assert pt1 + pt2 == pt3


if __name__ == "__main__":
    m1 = random.getrandbits(int(math.log2(POWER)) * 2)
    m2 = random.getrandbits(int(math.log2(POWER)) * 2)

    print("Testing scheme1")
    testScheme1(m1, m2)

    print("Testing scheme3")
    testScheme3(m1, m2)

    print("Testing precompute_gm")
    testPrecomputeGm(m1, m2)

    print("Testing precompute_gnr")
    testPrecomputeGnr(m1, m2)

    print("Testing precompute_both")
    testPrecomputeBoth(m1, m2)

    print("Finished successfully")
