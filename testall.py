import math

from Cryptodome.Random import random

from schemes import scheme1, scheme3, opt1, opt2, opt3
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


def testOpt1(m1, m2):
    ps = opt1.PaillierScheme.constructFromJsonFile(
        "opt1-2022-01-06_22:16:03.993283.json"
    )

    ct1 = ps.encrypt(m1)
    ct2 = ps.encrypt(m2)

    pt1 = ps.decrypt(ct1)
    pt2 = ps.decrypt(ct2)

    pt3 = ps.decrypt(ps.add_two_ciphertexts(ct1, ct2))

    assert pt1 == m1
    assert pt2 == m2
    assert pt1 + pt2 == pt3


def testOpt2(m1, m2):
    ps = opt2.PaillierScheme.constructFromJsonFile(
        "opt3-2022-01-07_14.47.27.047353.json"
    )

    ct1 = ps.encrypt(m1)
    ct2 = ps.encrypt(m2)

    pt1 = ps.decrypt(ct1)
    pt2 = ps.decrypt(ct2)

    pt3 = ps.decrypt(ps.add_two_ciphertexts(ct1, ct2))

    assert pt1 == m1
    assert pt2 == m2
    assert pt1 + pt2 == pt3


def testOpt3(m1, m2):
    ps = opt3.PaillierScheme.constructFromJsonFile(
        "opt3-2022-01-07_14.47.27.047353.json"
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

    print("Testing opt1")
    testOpt1(m1, m2)

    print("Testing opt2")
    testOpt2(m1, m2)

    print("Testing opt3")
    testOpt3(m1, m2)

    print("Finished successfully")
