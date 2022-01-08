import math
import timeit

from Cryptodome.Random import random

from schemes import scheme1, scheme3, opt1, opt2, opt3
from schemes.config import POWER


ps = scheme1.PaillierScheme()
message = random.getrandbits(int(math.log2(POWER)) * 2)

temp = timeit.timeit(lambda: ps.encrypt(message), number=10)

pass