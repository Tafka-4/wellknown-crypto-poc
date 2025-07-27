import os
import sys
import time
import string
from functools import partial
from Crypto.Cipher import AES
from multiprocessing import Pool, cpu_count

SECRET_KEY = os.urandom(16)
SECRET_IV = os.urandom(16)
BLOCK_SIZE = AES.block_size
TARGET_PLAINTEXT_SUFFIX = b'flag{vulnerable_aes_cbc_mode_using_same_iv}'
CHARSET = string.ascii_letters + string.digits + "_-{}! "
CHARSET_BYTES = CHARSET.encode('utf-8')

def pkcs7_pad(d, bs): return d + bytes([bs - len(d) % bs] * (bs - len(d) % bs))
def pkcs7_unpad(pd, bs):
    if not pd: return b''
    p = pd[-1]
    if p > bs or p == 0 or pd[-p:] != bytes([p]) * p: return pd
    return pd[:-p]

def encryption_oracle(user_input: bytes):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, SECRET_IV)
    padded_plaintext = pkcs7_pad(user_input + TARGET_PLAINTEXT_SUFFIX, BLOCK_SIZE)
    return cipher.encrypt(padded_plaintext)

def check_payload(payload: bytes, target_cipher_block: bytes, block_start_idx: int, block_end_idx: int):
    oracle_output = encryption_oracle(payload)
    if oracle_output[block_start_idx:block_end_idx] == target_cipher_block:
        return payload[-1:]
    return None

def recover_flag_attack():
    num_workers = cpu_count()
    print(f"Parallel processing: Starting attack with {num_workers} worker processes.")
    print("-" * 30)
    
    start_time = time.time()
    recovered_plaintext = b''
    
    with Pool(processes=num_workers) as pool:
        max_length_to_recover = len(TARGET_PLAINTEXT_SUFFIX) + BLOCK_SIZE
        for i in range(max_length_to_recover):
            block_index = i // BLOCK_SIZE
            padding_len = BLOCK_SIZE - 1 - (i % BLOCK_SIZE)
            padding = b'A' * padding_len

            block_start_idx = block_index * BLOCK_SIZE
            block_end_idx = block_start_idx + BLOCK_SIZE
            target_cipher_block = encryption_oracle(padding)[block_start_idx:block_end_idx]
            
            prefix = padding + recovered_plaintext
            payloads = [prefix + bytes([byte_val]) for byte_val in CHARSET_BYTES]
            
            worker_func = partial(check_payload, 
                                  target_cipher_block=target_cipher_block, 
                                  block_start_idx=block_start_idx, 
                                  block_end_idx=block_end_idx)

            found_byte = None
            for result in pool.imap_unordered(worker_func, payloads):
                if result:
                    found_byte = result
                    break
            
            if found_byte is None:
                all_other_bytes = bytes(sorted(list(set(range(256)) - set(CHARSET_BYTES))))
                payloads = [prefix + bytes([byte_val]) for byte_val in all_other_bytes]
                for result in pool.imap_unordered(worker_func, payloads):
                    if result:
                        found_byte = result
                        break
            
            if found_byte is None:
                print(f"\n[!] Failed to find {i}th byte. Stopping attack.")
                break

            recovered_plaintext += found_byte
            
            sys.stdout.write(f"\r[+] Recovered plaintext: {recovered_plaintext.decode(errors='ignore')}")
            sys.stdout.flush()

            if len(recovered_plaintext) > 1 and recovered_plaintext[-1] in range(1, BLOCK_SIZE + 1):
                pad_val = recovered_plaintext[-1]
                if recovered_plaintext[-pad_val:] == bytes([pad_val]) * pad_val:
                    print(f"\n[+] PKCS#7 padding ({pad_val} bytes) detected. Ending attack early.")
                    recovered_plaintext = pkcs7_unpad(recovered_plaintext, BLOCK_SIZE)
                    break

    sys.stdout.write(f"\r[+] Recovered plaintext: {recovered_plaintext.decode(errors='ignore')}   \n")
    end_time = time.time()
    
    print("\n" + "-" * 30)
    print("Attack finished.")
    print(f"\n[+] Final recovered plaintext: {recovered_plaintext.decode(errors='ignore')}")
    print(f"[+] Original plaintext:       {TARGET_PLAINTEXT_SUFFIX.decode()}")
    print(f"[+] Total time taken: {end_time - start_time:.2f} seconds")

if __name__ == '__main__':
    recover_flag_attack()
