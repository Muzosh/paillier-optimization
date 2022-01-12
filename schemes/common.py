import os
from functools import reduce

PARAMS_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "params"
)


# Paillier's L-function
def Lfunction(u: int, n: int) -> int:
    return (u - 1) // n

def chinese_remainder(m: list, a: list) -> int:
    """
    Chinese remainder theorem from
    https://medium.com/analytics-vidhya/chinese-remainder-theorem-using-python-25f051e391fc
    
    Finds A for:
        A = a1 (mod m1) \\
        A = a2 (mod m2) \\
        A = a3 (mod m3) and so on...

    Args:
        m (list): list of m1, m2, m3, ...
        a (list): list of a1, a2, a3, ...

    Returns:
        int: returns A
    """
    total = 0
    prod = reduce(lambda acc, b: acc * b, m)
    for n_i, a_i in zip(m, a):
        p = prod // n_i
        total += a_i * pow(p, -1, n_i) * p
    return total % prod
