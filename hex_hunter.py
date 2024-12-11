import os
import time
import random
import hashlib
import base58
import ecdsa
from multiprocessing import Pool, cpu_count
from Crypto.Hash import RIPEMD160
from colorama import Fore, Style, init

init(autoreset=True)

DATABASE = r'database/BTC_12_3_2024/'

# Function to convert private key (hex) to Bitcoin addresses
def private_key_to_addresses(private_key):
    private_key_bytes = bytes.fromhex(private_key)

    # Generate the public key (uncompressed)
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    uncompressed_public_key = b'\x04' + vk.to_string()

    # Generate the uncompressed address (P2PKH)
    sha256_hash = hashlib.sha256(uncompressed_public_key).digest()
    ripemd160 = RIPEMD160.new(sha256_hash).digest()
    var_encoded = b'\x00' + ripemd160  # Prefix 0x00 for P2PKH
    checksum = hashlib.sha256(hashlib.sha256(var_encoded).digest()).digest()[:4]
    uncompressed_address = base58.b58encode(var_encoded + checksum).decode()

    # Generate the compressed public key
    prefix = b'\x02' if vk.to_string()[-1] % 2 == 0 else b'\x03'
    compressed_public_key = prefix + vk.to_string()[:32]

    # Generate the compressed address (P2PKH)
    sha256_hash_compressed = hashlib.sha256(compressed_public_key).digest()
    ripemd160_compressed = RIPEMD160.new(sha256_hash_compressed).digest()
    var_encoded_compressed = b'\x00' + ripemd160_compressed
    checksum_compressed = hashlib.sha256(hashlib.sha256(var_encoded_compressed).digest()).digest()[:4]
    compressed_address = base58.b58encode(var_encoded_compressed + checksum_compressed).decode()

    # Generate the Bech32 (SegWit) Address (P2WPKH)
    bech32_address = encode_bech32('bc', [0] + convertbits(ripemd160_compressed, 8, 5))

    # Generate the P2SH (P2WPKH in P2SH) Address
    redeem_script = b'\x00\x14' + ripemd160_compressed
    redeem_script_hash = hashlib.sha256(redeem_script).digest()
    ripemd160_redeem = RIPEMD160.new(redeem_script_hash).digest()
    p2sh_address = base58.b58encode(b'\x05' + ripemd160_redeem + hashlib.sha256(hashlib.sha256(b'\x05' + ripemd160_redeem).digest()).digest()[:4]).decode()

    return uncompressed_address, compressed_address, bech32_address, p2sh_address

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits > 0:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def encode_bech32(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def check_key(private_key, database):
    uncompressed_address, compressed_address, bech32_address, p2sh_address = private_key_to_addresses(private_key)

    print(f"\n{Fore.YELLOW}Private Key (Hex): {Fore.LIGHTYELLOW_EX}{private_key}")
    print(f"{Fore.CYAN}Uncompressed Address (P2PKH): {Fore.LIGHTCYAN_EX}{uncompressed_address}")
    print(f"{Fore.GREEN}Compressed Address (P2PKH): {Fore.LIGHTGREEN_EX}{compressed_address}")
    print(f"{Fore.MAGENTA}Bech32 Address (P2WPKH): {Fore.LIGHTMAGENTA_EX}{bech32_address}")
    print(f"{Fore.RED}P2SH Address (P2WPKH in P2SH): {Fore.LIGHTRED_EX}{p2sh_address}")

    matches = [
        addr for addr in [uncompressed_address, compressed_address, bech32_address, p2sh_address]
        if addr in database

    ]
    if matches:
        print(f"{Fore.LIGHTGREEN_EX}Match Found! Addresses: {', '.join(matches)}")
        with open('HEX_HUNTER.txt', 'a') as BTC:
            BTC.write(f"Private Key (Hex): {private_key}\n")
            BTC.write(f"Uncompressed Address (P2PKH): {uncompressed_address}\n")
            BTC.write(f"Compressed Address (P2PKH): {compressed_address}\n")
            BTC.write(f"Bech32 Address (P2WPKH): {bech32_address}\n")
            BTC.write(f"P2SH Address (P2WPKH in P2SH): {p2sh_address}\n")
            BTC.write(f"Matched Addresses: {', '.join(matches)}\n\n")
    else:
        print(f"{Fore.LIGHTRED_EX}No Matches Found.")
        

def worker(database):
    generated_keys = 0
    found_addresses = 0
    start_time = time.time()

    while True:
        private_key = '{:064x}'.format(random.getrandbits(256))
        uncompressed_address, compressed_address, bech32_address, p2sh_address = private_key_to_addresses(private_key)
        found = False

        for address in [uncompressed_address, compressed_address, bech32_address, p2sh_address]:
            if address in database:
                found = True
                with open('HEX_HUNTER.txt', 'a') as BTC:
                    BTC.write(f"Private Key (Hex): {private_key}\n")
                    BTC.write(f"Uncompressed Address (P2PKH): {uncompressed_address}\n")
                    BTC.write(f"Compressed Address (P2PKH): {compressed_address}\n")
                    BTC.write(f"Bech32 Address (P2WPKH): {bech32_address}\n")
                    BTC.write(f"P2SH Address (P2WPKH in P2SH): {p2sh_address}\n\n")
                break

        if found:
            found_addresses += 1

        generated_keys += 1

        if generated_keys % 5000 == 0:
            elapsed_time = time.time() - start_time
            keys_per_second = generated_keys / elapsed_time
            print("=" * 60)
            print(f"{Fore.LIGHTYELLOW_EX}Keys Generated: {generated_keys} | Found: {found_addresses} | Speed: {keys_per_second:.2f} keys/s")
            print(f"{Fore.YELLOW}Private Key (Hex): {private_key}")
            print(f"{Fore.CYAN}Uncompressed Address (P2PKH): {uncompressed_address}")
            print(f"{Fore.GREEN}Compressed Address (P2PKH): {compressed_address}")
            print(f"{Fore.MAGENTA}Bech32 Address (P2WPKH): {bech32_address}")
            print(f"{Fore.RED}P2SH Address (P2WPKH in P2SH): {p2sh_address}")
            print("=" * 60)

def main():
    print(f"{Fore.LIGHTMAGENTA_EX}Reading database files...")
    database = set()
    address_count = 0

    for filename in os.listdir(DATABASE):
        with open(DATABASE + filename) as file:
            for address in file:
                address = address.strip()
                if address:
                    database.add(address)
                    address_count += 1

    print(f"{Fore.LIGHTGREEN_EX}Loaded {address_count} addresses.")
    print(f"{Fore.LIGHTYELLOW_EX}Available CPU Cores: {cpu_count()}")
    print("\nChoose an option:")
    print(f"{Fore.CYAN}1. Generate random keys")
    print(f"{Fore.GREEN}2. Check specific private key")
    choice = input(f"{Fore.LIGHTMAGENTA_EX}Enter your choice (1 or 2): ")

    if choice == '1':
        num_cores = int(input(f"{Fore.LIGHTYELLOW_EX}How many CPU cores would you like to use? "))
        print(f"{Fore.LIGHTCYAN_EX}Starting the process with {num_cores} cores...")
        with Pool(num_cores) as pool:
            pool.map(worker, [database] * num_cores)
    elif choice == '2':
        private_key = input(f"{Fore.LIGHTYELLOW_EX}Enter the private key (hex): ").strip()
        check_key(private_key, database)
    else:
        print(f"{Fore.LIGHTRED_EX}Invalid choice. Exiting.")

if __name__ == '__main__':
    main()
