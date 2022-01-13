import json
import math
import os
from datetime import datetime
from timeit import default_timer as timer

from Cryptodome.Random import random

from schemes import (
    precompute_both_scheme,
    precompute_gm_scheme,
    precompute_gnr_scheme,
    scheme1,
    scheme3,
)
from schemes.config import CHEAT, DEFAULT_KEYSIZE, NO_GNR, POWER

BATCH_SIZE = 50

RESULTS_PATH = os.path.join(os.path.dirname(__file__), "results")


def fillTimesScheme1(messages, results):
    print("Starting Scheme1 filling...")
    ps = scheme1.PaillierScheme()
    print("Scheme1 loaded")

    for index, message in enumerate(messages):
        print(f"Scheme1: iteration {index+1} out of {BATCH_SIZE}")
        start = timer()
        ct = ps.encrypt(message)
        middle = timer()
        pt = ps.decrypt(ct)
        end = timer()

        if pt == message:
            results["scheme1"]["enc"].append(middle - start)
            results["scheme1"]["dec"].append(end - middle)
        else:
            raise ValueError("Scheme1: Decrypted is not the same as message")


def fillTimesScheme3(messages, results):
    print("Starting Scheme3 filling...")
    ps = scheme3.PaillierScheme()
    print("Scheme3 loaded")

    for index, message in enumerate(messages):
        print(f"Scheme3: iteration {index+1} out of {BATCH_SIZE}")
        start = timer()
        ct = ps.encrypt(message)
        middle = timer()
        pt = ps.decrypt(ct)
        end = timer()

        if pt == message:
            results["scheme3"]["enc"].append(middle - start)
            results["scheme3"]["dec"].append(end - middle)
        else:
            raise ValueError("Scheme3: Decrypted is not the same as message")


def fillTimesPrecomputeGm(messages, results):
    print("Starting precompute_gm filling...")
    ps = precompute_gm_scheme.PaillierScheme.constructFromJsonFile(
        "gm-2022-01-06_22:16:03.993283.json"
    )
    print("precompute_gm loaded")

    for index, message in enumerate(messages):
        print(f"precompute_gm: iteration {index+1} out of {BATCH_SIZE}")
        start = timer()
        ct = ps.encrypt(message)
        middle = timer()
        pt = ps.decrypt(ct)
        end = timer()

        if pt == message:
            results["precompute_gm"]["enc"].append(middle - start)
            results["precompute_gm"]["dec"].append(end - middle)
        else:
            raise ValueError(
                "precompute_gm: Decrypted is not the same as message"
            )


def fillTimesPrecomputeGnr(messages, results):
    print("Starting precompute_gnr filling...")
    ps = precompute_gnr_scheme.PaillierScheme.constructFromJsonFile(
        "both-2022-01-07_14.47.27.047353.json"
    )
    print("precompute_gnr loaded")

    for index, message in enumerate(messages):
        print(f"precompute_gnr: iteration {index+1} out of {BATCH_SIZE}")
        start = timer()
        ct = ps.encrypt(message)
        middle = timer()
        pt = ps.decrypt(ct)
        end = timer()

        if pt == message:
            results["precompute_gnr"]["enc"].append(middle - start)
            results["precompute_gnr"]["dec"].append(end - middle)
        else:
            raise ValueError(
                "precompute_gnr: Decrypted is not the same as message"
            )


def fillTimesBoth(messages, results):
    print("Starting precompute_both filling...")
    ps = precompute_both_scheme.PaillierScheme.constructFromJsonFile(
        "both-2022-01-07_14.47.27.047353.json"
    )
    print("precompute_both loaded")

    for index, message in enumerate(messages):
        print(f"precompute_both: iteration {index+1} out of {BATCH_SIZE}")
        start = timer()
        ct = ps.encrypt(message)
        middle = timer()
        pt = ps.decrypt(ct)
        end = timer()

        if pt == message:
            results["precompute_both"]["enc"].append(middle - start)
            results["precompute_both"]["dec"].append(end - middle)
        else:
            raise ValueError(
                "precompute_both: Decrypted is not the same as message"
            )


if __name__ == "__main__":

    messages = [
        random.getrandbits(int(math.log2(POWER)) * 2)
        for _ in range(BATCH_SIZE)
    ]

    results = {
        "cheat": CHEAT,
        "no_gnr": NO_GNR,
        "power": POWER,
        "default_keysize": DEFAULT_KEYSIZE,
        "scheme1": {"enc": [], "dec": []},
        "scheme3": {"enc": [], "dec": []},
        "precompute_gm": {"enc": [], "dec": []},
        "precompute_gnr": {"enc": [], "dec": []},
        "precompute_both": {"enc": [], "dec": []},
    }

    fillTimesScheme1(messages, results)
    fillTimesScheme3(messages, results)
    fillTimesPrecomputeGm(messages, results)
    fillTimesPrecomputeGnr(messages, results)
    fillTimesBoth(messages, results)

    file_path = os.path.join(
        RESULTS_PATH,
        (
            "results-"
            + str(datetime.now()).replace(" ", "_").replace(":", ".")
            + ".json"
        ),
    )

    print(f"Results file path: {file_path}")

    if not os.path.exists(RESULTS_PATH):
        os.mkdir(RESULTS_PATH)

    with open(
        file_path,
        "w",
        encoding="ISO-8859-2",
    ) as file:
        json.dump(results, file)

    print("Finished successfully")
