# HEX_HUNTER Bitcoin Brute Forcer

A Bitcoin wallet collider that brute forces random wallet addresses

# Like This Project? Give It A Star

# Dependencies

<a href="https://www.python.org/downloads/">Python 3.9</a> or higher

Python modules listed in the <a href="/requirements.txt">requirements.txt<a/>

If you have a __Linux__ or __MacOS__ operating system, libgmp3-dev is required. If you have __Windows__ then this is not required. Install by running the command:
```
sudo apt-get install libgmp3-dev
```

# Installation

```
git clone https://github.com/codesorcerer0/hex_hunter.git
```
```
cd hex_hunter && pip3 install -r requirements.txt
```

# Quick Start

```
python3 hex_hunter.py
```

# Proof Of Concept

A private key is a secret number that allows Bitcoins to be spent. If a wallet has Bitcoins in it, then the private key will allow a person to control the wallet and spend whatever balance the wallet has. So this program attempts to find Bitcoin private keys that correlate to wallets with positive balances. However, because it is impossible to know which private keys control wallets with money and which private keys control empty wallets, we have to randomly look at every possible private key that exists and hope to find one that has a balance.

This program is essentially a brute forcing algorithm. It continuously generates random Bitcoin private keys, converts the private keys into their respective wallet addresses, then check if match against database addresses with balance, If any match it will be save to `found.txt` on the user's hard drive. The ultimate goal is to randomly find a wallet with a balance out of the 2<sup>160</sup> possible wallets in existence. 

# How It Works

32 byte hexidecimal strings are generated randomly using `os.urandom()` and are used as our private keys.

The private keys are converted into their respective public keys using the `ecdsa` python library. This is the fastest library to perform secp256k1 signing. so instead we use `ecdsa` to generate public keys. The public keys are converted into their Bitcoin wallet addresses using the `binascii` and `hashlib` standard libraries.

This program also utilizes multiprocessing through the `multiprocessing.Process()` function in order to make concurrent calculations.

# Efficiency

It takes `0.001` seconds for this progam to brute force a __single__ Bitcoin address. 

However, through `multiprocessing.Process()` a concurrent process is created for every CPU your computer has. So this program can brute force a single address at a speed of `0.001 ÷ cpu_count()` seconds.

# Database FAQ

An offline database is used to find the balance of generated Bitcoin addresses. Visit <a href="/database/">/database</a> for information.

# Parameters

This program has optional parameters to customize how it runs:

maximum number of cores

By default the program runs using `python3 hex_hunter.py` if nothing is passed.
  
# Expected Output

If a wallet with a balance is found, then all necessary information about the wallet will be saved to the text file `found.txt`. An example is:

>Private Key (Hex): 5A4F3F1CAB44848B2C2C515AE74E9CC487A9982C9DD695810230EA48B1DCEADD<br/>
>Uncompressed Address (P2PKH): 1Kz2CTvjzkZ3p2BQb5x5DX6GEoHX2jFS45<br/>
>Compressed Address (P2PKH): 1Mgxr5kB3nfjCAoRhwMLzKKjPaHkAjFxzm<br/>
>Bech32 Address (P2WPKH): bc1qutc4kd8esk3w5djrwpmfuravc5myfa86ax4lmk<br/>
>P2SH Address (P2WPKH in P2SH): 3BxonbaA1n5mxEJHzNJs2P3qPNnBLq2HTq<br/>
>Matched Addresses: bc1qutc4kd8esk3w5djrwpmfuravc5myfa86ax4lmk<br/>

# for donation 
bc1qdgzh422l7xgkgzmctr0njr0fp966wwche4jx0e

# HOPE IT WILL HELP
[FOR ANY QUESTIONS TEXT US AT]

> code_crusaders :: https://t.me/code_Crusaders0/1
> KEYFOUND ::  https://t.me/privatekeydirectorygroup

# CONTACT :: 
> US THROUGH DRIECT MESSAGES ON TELE : @CodeSorcerer0 / https://t.me/CodeSorcerer0

# Recent Improvements & TODO

<a href="https://github.com/codesorcerer0/hex_hunter/issues">Create an issue</a> so I can add more stuff to improve
