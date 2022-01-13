import json
import os
import statistics

import matplotlib.pyplot as plt


def plot(file_path):
    schemes_path = os.path.join(os.path.dirname(__file__), "schemes")
    if not os.path.exists(schemes_path):
        raise LookupError(f"Scehemes directory does not exist: {schemes_path}")

    schemes = [
        e.replace("_scheme.py", "").replace(".py", "")
        for e in os.listdir(schemes_path)
        if e not in ("__init__.py", "__pycache__", "common.py", "config.py")
    ]

    data = {}
    with open(file_path, encoding="ISO-8859-2") as file:
        data = json.load(file)

    schemes_with_means = sorted(
        [
            (
                scheme,
                statistics.mean(
                    [time * (10 ** 3) for time in data[scheme]["enc"]] or [0]
                ),
                statistics.mean(
                    [time * (10 ** 3) for time in data[scheme]["dec"]] or [0]
                ),
            )
            for scheme in schemes
        ],
        key=lambda x: x[1],
        reverse=True,
    )

    plt.subplot(1, 2, 1)
    for scheme, mean, _ in schemes_with_means:
        plt.plot(
            [i + 1 for i in range(len(data[scheme]["enc"]))],
            [time * (10 ** 3) for time in data[scheme]["enc"]],
            "x-",
            label=scheme + " - avg: " + "%.2f" % mean,
        )
    plt.xlabel("Iteration")
    plt.ylabel("Execution time [ms]")
    plt.title("Encryption times in miliseconds")
    plt.legend()

    plt.subplot(1, 2, 2)
    for scheme, _, mean in schemes_with_means:
        plt.plot(
            [i + 1 for i in range(len(data[scheme]["dec"]))],
            [time * (10 ** 3) for time in data[scheme]["dec"]],
            "x-",
            label=scheme + " - avg: " + "%.2f" % mean,
        )
    plt.xlabel("Iteration")
    plt.ylabel("Execution time [ms]")
    plt.title("Decryption times in miliseconds")
    plt.legend()

    plt.suptitle(
        "Paillier encryption scheme optimalization - CHEAT: "
        + str(data["cheat"])
    )
    plt.show()


if __name__ == "__main__":
    results_path = os.path.join(os.path.dirname(__file__), "results")

    if not os.path.exists(results_path):
        os.mkdir(results_path)

    filelist = os.listdir(results_path)
    filelist.sort()

    print("--------------------------------------")
    for index, filename in enumerate(filelist):
        print(f"{index}: {filename}")
    print("--------------------------------------")
    choice = input("Choose file index or add own path for results: ")

    if str.isnumeric(choice):
        filename = os.path.join(
            os.path.dirname(__file__), "results", filelist[int(choice)]
        )
    elif os.path.exists(choice):
        filename = choice
    else:
        raise LookupError(f"Results file does not exist: {choice}")

    plot(filename)
