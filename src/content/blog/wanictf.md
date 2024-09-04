---
title: 'wanictf 2024 challenges'
description: 'Solutions I did for WaniCTF 2024'
pubDate: 'May 01 2024'
heroImage: 
  src: '/blog-placeholder-1.jpg'
  alt: ''
order: 1
tags: ["writeup"]
---

# Background Information
I went to this competition as perpendicular pineapples. Could only do some of the challenges, which were mostly the beginner ones.

## Cryptography

#### Beginner AES

> AES is one of the most important encryption methods in our daily lives.

Let's look at the provided code that encrypts the flag.

```python
# https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from os import urandom
import hashlib

key = b'the_enc_key_is_'
iv = b'my_great_iv_is_'
key += urandom(1)
iv += urandom(1)

cipher = AES.new(key, AES.MODE_CBC, iv)
FLAG = b'FLAG{This_is_a_dummy_flag}'
flag_hash = hashlib.sha256(FLAG).hexdigest()

msg = pad(FLAG, 16)
enc = cipher.encrypt(msg)

print(f'enc = {enc}') # bytes object
print(f'flag_hash = {flag_hash}') # str object
```

So we can see that the last character in both key and iv are random, and we can also see that the flag is encrypted using AES. 

We are also provide a `out.txt` file, which has the encrypted flag as well as the hash of the flag

```bash
enc = b'\x16\x97,\xa7\xfb_\xf3\x15.\x87jKRaF&"\xb6\xc4x\xf4.K\xd77j\xe5MLI_y\xd96\xf1$\xc5\xa3\x03\x990Q^\xc0\x17M2\x18'
flag_hash = 6a96111d69e015a07e96dcd141d31e7fc81c4420dbbef75aef5201809093210e
```

So here's our solution: We iterate through all potential 255 bytes for both the key and iv and check if the flag is encrypted. 

Here's our solve script:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import hashlib

# Given encrypted data and original key/iv with appended bytes
enc = b'\x16\x97,\xa7\xfb_\xf3\x15.\x87jKRaF&"\xb6\xc4x\xf4.K\xd77j\xe5MLI_y\xd96\xf1$\xc5\xa3\x03\x990Q^\xc0\x17M2\x18'  # Example encrypted data
original_key = b'the_enc_key_is_'
original_iv = b'my_great_iv_is_'

# Original flag and its hash
flag_hash = "6a96111d69e015a07e96dcd141d31e7fc81c4420dbbef75aef5201809093210e"

# Brute-force through all possible key and iv combinations
for key_byte in range(256):
    for iv_byte in range(256):
        # Append the guessed byte to the original key and iv
        key = original_key + bytes([key_byte])
        iv = original_iv + bytes([iv_byte])

        # Create AES cipher object
        cipher = AES.new(key, AES.MODE_CBC, iv)

        try:
            # Decrypt the encrypted data
            decrypted_data = cipher.decrypt(enc)

            # Unpad the decrypted data
            plaintext = unpad(decrypted_data, AES.block_size)

            # Calculate SHA-256 hash of the plaintext
            sha256_hash = hashlib.sha256(plaintext).hexdigest()

            # Compare with original flag hash
            if sha256_hash == flag_hash:
                print(f"Decrypted flag: {plaintext.decode('utf-8')}")
                print(f"Guessed Key: {key}")
                print(f"Guessed IV: {iv}")
                break  # Exit the loop if flag is found

        except ValueError:
            # Incorrect decryption (padding error), continue to next key/iv combination
            continue

    else:
        continue  # Continue outer loop if flag not found
    break  # Exit outer loop if flag is found
```

#### Beginner RSA

> Do you know RSA?

Let's look at the source code provided:

```python
from Crypto.Util.number import *

p = getPrime(64)
q = getPrime(64)
r = getPrime(64)
s = getPrime(64)
a = getPrime(64)
n = p*q*r*s*a
e = 0x10001

FLAG = b'FLAG{This_is_a_fake_flag}'
m = bytes_to_long(FLAG)
enc = pow(m, e, n)
print(f'n = {n}')
print(f'e = {e}')
print(f'enc = {enc}')
```
```bash
n = 317903423385943473062528814030345176720578295695512495346444822768171649361480819163749494400347
e = 65537
enc = 127075137729897107295787718796341877071536678034322988535029776806418266591167534816788125330265
```

We can see 5 primes are used in our encryption. Interesting. 

Since the factors are all small, we can just go to factorDB and get the factors using the composite number `n`. We then can create a private key that will decrypt the encrypted `enc`

Here's the solve script:

```python
def inverse(x, m):
  a, b, u = 0, m, 1
  while x > 0:
    q = b // x
    x, a, b, u = b % x, u, x, a - q * u
  if b == 1:
    return a % m
n = 317903423385943473062528814030345176720578295695512495346444822768171649361480819163749494400347
e = 65537
enc = 127075137729897107295787718796341877071536678034322988535029776806418266591167534816788125330265

p = 9953162929836910171
q = 11771834931016130837
r = 12109985960354612149
s = 13079524394617385153
a = 17129880600534041513

factors = [9953162929836910171, 11771834931016130837, 12109985960354612149, 13079524394617385153, 17129880600534041513]
phi = 1
for p in factors:
    phi *= (p - 1)
d = inverse(e, phi)
M = bytes.fromhex(hex(pow(enc, d,n))[2:]).decode()
print(M)
#https://ctftime.org/writeup/21831
```

## Web Exploitatoin
#### Bad Worker

> オフラインで動くウェブアプリをつくりました。 We created a web application that works offline. https://web-bad-worker-lz56g6.wanictf.org

This one was kind of confusing. Looking into the web app, we can see that theres a route that will fetch `flag.txt`

However, when we try to interact by requesting it in the web server we get nothing! Even downloading the web app offline doesn't do anything!

However, you can just try to request the file `flag.txt` yourself, which does yield the flag.

```bash
wget https://web-bad-worker-lz56g6.wanictf.org/FLAG.txt
```

#### pow

> compute hash to get your flag
> ハッシュを計算してフラグを取ろう

Upon visiting the website, we can see that hashes are being 'computed', but we need 1,000,000 to get the flag. 

IN NO WAY ON EARTH I AM WAITING TO COMPUTE 1000000 HASHES. LET'S GET LAZY.

So the hashes computed is sent as a post request, but you can intentionally send the same hash and it counts as a hash, increasing the computed hash count.

So what we can do is repeatedly send the same hash to the server until 1000000 hashes are computed. My solve script was really messy, but it did the job.

```bash
#!/bin/bash

# Define the URL for the curl request

# Number of times to repeat the curl request
REPEAT_TIMES=1000000

# Loop to repeat curl request
for (( i=1; i<=$REPEAT_TIMES; i++ ))
do
    # Perform curl request (adjust options as needed)
    curl 'https://web-pow-lz56g6.wanictf.org/api/pow' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0' -H 'Accept: */*' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br, zstd' -H 'Referer: https://web-pow-lz56g6.wanictf.org/' -H 'Origin: https://web-pow-lz56g6.wanictf.org' -H 'Connection: keep-alive' -H 'Cookie: pow_session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXNzaW9uSWQiOiJjYmNlZGI1OS1iOGQ1LTRkYmMtOGYyZC1iNTAyOWY3NzI1MzUifQ.yKnE98ZeLTmQ7YRgZkRUkk2bocPV8eurrm8gTgxRg6M' -H 'Sec-Fetch-Dest: empty' -H 'Sec-Fetch-Mode: no-cors' -H 'Sec-Fetch-Site: same-origin' -H 'TE: trailers' -H 'Content-Type: application/json' -H 'Alt-Used: web-pow-lz56g6.wanictf.org' -H 'Priority: u=4' -H 'Pragma: no-cache' -H 'Cache-Control: no-cache' --data-raw '["2862152","2862152","2862152","2862152","2862152","2862152","2862152","2862152","2862152","2862152", ...]
 sleep 1
done
```

## Reverse Engineering
#### lambda
> Let's dance with lambda!

Let's look at the source code we have to decrypt. 

```python
import sys

sys.setrecursionlimit(10000000)

(lambda _0: _0(input))(lambda _1: (lambda _2: _2('Enter the flag: '))(lambda _3: (lambda _4: _4(_1(_3)))(lambda _5: (lambda _6: _6(''.join))(lambda _7: (lambda _8: _8(lambda _9: _7((chr(ord(c) + 12) for c in _9))))(lambda _10: (lambda _11: _11(''.join))(lambda _12: (lambda _13: _13((chr(ord(c) - 3) for c in _10(_5))))(lambda _14: (lambda _15: _15(_12(_14)))(lambda _16: (lambda _17: _17(''.join))(lambda _18: (lambda _19: _19(lambda _20: _18((chr(123 ^ ord(c)) for c in _20))))(lambda _21: (lambda _22: _22(''.join))(lambda _23: (lambda _24: _24((_21(c) for c in _16)))(lambda _25: (lambda _26: _26(_23(_25)))(lambda _27: (lambda _28: _28('16_10_13_x_6t_4_1o_9_1j_7_9_1j_1o_3_6_c_1o_6r'))(lambda _29: (lambda _30: _30(''.join))(lambda _31: (lambda _32: _32((chr(int(c,36) + 10) for c in _29.split('_'))))(lambda _33: (lambda _34: _34(_31(_33)))(lambda _35: (lambda _36: _36(lambda _37: lambda _38: _37 == _38))(lambda _39: (lambda _40: _40(print))(lambda _41: (lambda _42: _42(_39))(lambda _43: (lambda _44: _44(_27))(lambda _45: (lambda _46: _46(_43(_45)))(lambda _47: (lambda _48: _48(_35))(lambda _49: (lambda _50: _50(_47(_49)))(lambda _51: (lambda _52: _52('Correct FLAG!'))(lambda _53: (lambda _54: _54('Incorrect'))(lambda _55: (lambda _56: _56(_41(_53 if _51 else _55)))(lambda _57: lambda _58: _58)))))))))))))))))))))))))))
```

Wow. Very messy. But don't get scared. We can simply just split this into smaller parts, and reverse the operations to get the flag.

Here's the solution script:

```python
import sys

sys.setrecursionlimit(10000000)

(lambda _0: _0(input))
(lambda _1: (lambda _2: _2('Enter the flag: '))

(lambda _3: (lambda _4: _4(_1(_3)))
(lambda _5: (lambda _6: _6(''.join))
#
(lambda _7: (lambda _8: _8(lambda _9: _7((chr(ord(c) + 12) for c in _9))))
(lambda _10: (lambda _11: _11(''.join))
(lambda _12: (lambda _13: _13((chr(ord(c) - 3) for c in _10(_5))))
(lambda _14: (lambda _15: _15(_12(_14)))
(lambda _16: (lambda _17: _17(''.join))
(lambda _18: (lambda _19: _19(lambda _20: _18((chr(123 ^ ord(c)) for c in _20))))
(lambda _21: (lambda _22: _22(''.join))
(lambda _23: (lambda _24: _24((_21(c) for c in _16)))
(lambda _25: (lambda _26: _26(_23(_25)))
(lambda _27: (lambda _28: _28('16_10_13_x_6t_4_1o_9_1j_7_9_1j_1o_3_6_c_1o_6r'))
(lambda _29: (lambda _30: _30(''.join))
(lambda _31: (lambda _32: _32((chr(int(c,36) + 10) for c in _29.split('_'))))
(lambda _33: (lambda _34: _34(_31(_33)))(lambda _35: (lambda _36: _36(lambda _37: lambda _38: _37 == _38))
(lambda _39: (lambda _40: _40(print))(lambda _41: (lambda _42: _42(_39))
(lambda _43: (lambda _44: _44(_27))
(lambda _45: (lambda _46: _46(_43(_45)))
(lambda _47: (lambda _48: _48(_35))(lambda _49: (lambda _50: _50(_47(_49)))
(lambda _51: (lambda _52: _52('Correct FLAG!'))
(lambda _53: (lambda _54: _54('Incorrect'))(lambda _55: (lambda _56: _56(_41(_53 if _51 else _55)))(lambda _57: lambda _58: _58)))))))))))))))))))))))))))

#something plus twelve

#something -3 

#something xor


stuff = "16_10_13_x_6t_4_1o_9_1j_7_9_1j_1o_3_6_c_1o_6r" #this is what we have
stuff = stuff.split('_')
stuff = [chr(int(c,36)+ 10) for c in stuff]
stuff = [chr(ord(c) ^ 123) for c in stuff]
stuff = [chr(ord(c)+3) for c in stuff]
stuff = [chr(ord(c)-12) for c in stuff]
print(''.join(stuff))
```
