import json
import os
from statistics import mean

import matplotlib.pyplot as plt


def plot(file_path):
    schemes = ["scheme1", "scheme3", "opt1", "opt2", "opt3"]
    data = {}
    with open(file_path, encoding="ISO-8859-2") as file:
        data = json.load(file)

    plt.subplot(1, 2, 1)
    for scheme in schemes:
        plt.plot(
            [i + 1 for i in range(50)],
            [time * (10 ** 3) for time in data[scheme]["enc"]],
            "x-",
        )
    plt.xlabel("Iteration")
    plt.ylabel("Execution time [ms]")
    plt.title("Encryption times in miliseconds")
    plt.legend(
        [
            "scheme1 - avg: "
            + "%.2f"
            % mean([time * (10 ** 3) for time in data["scheme1"]["enc"]])
            + " ms",
            "scheme3 - avg: "
            + "%.2f"
            % mean([time * (10 ** 3) for time in data["scheme3"]["enc"]])
            + " ms",
            "opt1 - avg: "
            + "%.2f" % mean([time * (10 ** 3) for time in data["opt1"]["enc"]])
            + " ms",
            "opt2 - avg: "
            + "%.2f" % mean([time * (10 ** 3) for time in data["opt2"]["enc"]])
            + " ms",
            "opt3 - avg: "
            + "%.2f" % mean([time * (10 ** 3) for time in data["opt3"]["enc"]])
            + " ms",
        ]
    )

    plt.subplot(1, 2, 2)
    for scheme in schemes:
        plt.plot(
            [i + 1 for i in range(50)],
            [time * (10 ** 3) for time in data[scheme]["dec"]],
            "x-",
        )
    plt.xlabel("Iteration")
    plt.ylabel("Execution time [ms]")
    plt.title("Decryption times in miliseconds")
    plt.legend(
        [
            "scheme1 - avg: "
            + "%.2f"
            % mean([time * (10 ** 3) for time in data["scheme1"]["dec"]])
            + " ms",
            "scheme3 - avg: "
            + "%.2f"
            % mean([time * (10 ** 3) for time in data["scheme3"]["dec"]])
            + " ms",
            "opt1 - avg: "
            + "%.2f" % mean([time * (10 ** 3) for time in data["opt1"]["dec"]])
            + " ms",
            "opt2 - avg: "
            + "%.2f" % mean([time * (10 ** 3) for time in data["opt2"]["dec"]])
            + " ms",
            "opt3 - avg: "
            + "%.2f" % mean([time * (10 ** 3) for time in data["opt3"]["dec"]])
            + " ms",
        ]
    )

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
