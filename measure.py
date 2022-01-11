import json
import math
import os
from datetime import datetime
from timeit import default_timer as timer

from Cryptodome.Random import random

from schemes import opt1, opt2, opt3, scheme1, scheme3
from schemes.config import POWER, CHEAT, DEFAULT_KEYSIZE, NO_GNR

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


def fillTimesOpt1(messages, results):
    print("Starting Opt1 filling...")
    ps = opt1.PaillierScheme.constructFromJsonFile(
        "opt1-2022-01-06_22:16:03.993283.json"
    )
    print("Opt1 loaded")

    for index, message in enumerate(messages):
        print(f"Opt1: iteration {index+1} out of {BATCH_SIZE}")
        start = timer()
        ct = ps.encrypt(message)
        middle = timer()
        pt = ps.decrypt(ct)
        end = timer()

        if pt == message:
            results["opt1"]["enc"].append(middle - start)
            results["opt1"]["dec"].append(end - middle)
        else:
            raise ValueError("Opt1: Decrypted is not the same as message")


def fillTimesOpt2(messages, results):
    print("Starting Opt2 filling...")
    ps = opt2.PaillierScheme.constructFromJsonFile(
        "opt3-2022-01-07_14.47.27.047353.json"
    )
    print("Opt2 loaded")

    for index, message in enumerate(messages):
        print(f"Opt2: iteration {index+1} out of {BATCH_SIZE}")
        start = timer()
        ct = ps.encrypt(message)
        middle = timer()
        pt = ps.decrypt(ct)
        end = timer()

        if pt == message:
            results["opt2"]["enc"].append(middle - start)
            results["opt2"]["dec"].append(end - middle)
        else:
            raise ValueError("Opt2: Decrypted is not the same as message")


def fillTimesOpt3(messages, results):
    print("Starting Opt3 filling...")
    ps = opt3.PaillierScheme.constructFromJsonFile(
        "opt3-2022-01-07_14.47.27.047353.json"
    )
    print("Opt3 loaded")

    for index, message in enumerate(messages):
        print(f"Opt3: iteration {index+1} out of {BATCH_SIZE}")
        start = timer()
        ct = ps.encrypt(message)
        middle = timer()
        pt = ps.decrypt(ct)
        end = timer()

        if pt == message:
            results["opt3"]["enc"].append(middle - start)
            results["opt3"]["dec"].append(end - middle)
        else:
            raise ValueError("Opt3: Decrypted is not the same as message")


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
        "opt1": {"enc": [], "dec": []},
        "opt2": {"enc": [], "dec": []},
        "opt3": {"enc": [], "dec": []},
    }

    fillTimesScheme1(messages, results)
    fillTimesScheme3(messages, results)
    fillTimesOpt1(messages, results)
    fillTimesOpt2(messages, results)
    fillTimesOpt3(messages, results)

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
