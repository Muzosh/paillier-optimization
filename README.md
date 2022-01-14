# MOK project - Petr Muzikant

> this project implements *Encryption Performance Improvements of the Paillier Cryptosystem* by Christine Jost, Ha Lam, Alexander Maximov and Ben Smeets
>
> whitepaper is available here: <https://eprint.iacr.org/2015/864.pdf>

## Project structure and files

- `params` (dir) - scheme parameters and pre-compute values are stored here
- `results` (dir) - results from measurements by `measure.py` are stored here
- `schemes` (dir) - contains different versions of Paillier schemes
    - `common.py` - contains common code for all schemes
    - `config.py` - user can configurate common input values for all schemes (more in the [next chapter](#config))
    - `precompute_gm.py` - implements chapter *3.2 Computing $g^m mod\ n^2$* from the whitepaper (pre-computing message part) on top of `scheme3.py`
    - `precompute_gnr.py` - implements chapter *3.3 Computing $(g^n)^r mod\ n^2$* from the whitepaper (pre-computing noise part) on top of `scheme3.py`
    - `precompute_both.py` - implements combination of both pre-computations from `precompute_gm.py` and `precompute_gnr.py` on top of `scheme3.py`
    - `scheme1.py` - imlements original and basic form of Paillier cryptosystem
    - `scheme3.py` - implements Paillier's new variant with faster decryption
- `measure.py` - generates X random messages and encrypts them with all schemes, then generate file in `results`
- `plot.py` - creates plots with encryption and decryption times from all schemes from one file from `results`
- `testall.py` - tests all encryption schemes by generating message, encrypting it, decrypting it and checking if plaintext == message and checks if homomorphic properties hold

## Configuration

<div id="config"></div>
In `schemes/config.py` are these values waiting to be configured:

- `DEFAULT_KEYSIZE`: int - determines the bit-length of N since N is a public parameter (default=$2048$)
- `USE_PARALLEL`: bool - determines whether CPU parallelization should be used when pre-computing values (default=True)
- `POWER`: int - indirectly determines the number of values to be precomputed (default=$2^{16}$)
- `NO_GNR`: int - determines how many precomputed values of noise should be multiplied together (default=$5$)
- `CHEAT`: bool - some operations (mainly generation of r) requires knowledge of private key when doing an encryption, this violates principles of public key cryptography (default=False)
    - cheating brings some performance improvements

## Usage

### Schemes

Each scheme defines `PaillierScheme` class with `encrypt`, `decrypt`, `add_two_ciphertexts` functions and `private` + `public` dictionaries.

Depending on the scheme, there are additional functions for pre-computing and other logic.

*IN DEFAULT*, **schemes with pre-computing do this operation when called from constructor** (+ save parameters and pre-computed values to the `params` directory).

*IF YOU WANT TO LOAD PRE-COMPUTED VALUES AND PARAMETERS*, you need to **call static function `constructFromJsonFile`** with filename as argument.

### Measuring

In order to see the results of the performance improvements, one must first run `measure.py` with selected `BATCH_SIZE` (number of messages to be encrypted and decrypted). Please check functions `fillTimesXXX` for scheme creation (loading from json file is preffered since pre-computing takes time). This script creates another json file in `results` directory.

Some dummy parameters and values can be found [here](https://vutbr-my.sharepoint.com/:f:/g/personal/xmuzik08_vutbr_cz/EukPH0b5MPBNt6PfriKcKh8Bot8DD1u2x3h2W_bABpMHaQ?e=tZ6q07) (access is for @vutbr.cz only). Download them and put them into `params` project folder.

Please note, that for `precompute_gnr.PaillierScheme.constructFileFromJson` YOU CAN USE file computed for `precompute_both.py` which contain values needed for precompute_gnr (precompute_gnr is part of precompute_both).

### Plotting

Simply run `plot.py` script. At the start, it will give you option to choose from listed `results` directory by selecting filename index or to input your own path to results file.

After that, a figure will be plotted and shown to the user.
