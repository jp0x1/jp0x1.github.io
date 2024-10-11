---
title: 'android reversing suite (UPDATE ABANDONED)'
description: 'Some basic challenges based on android reversing. Will update as I solve more challenges'
pubDatetime: 2024-09-23T15:22:00Z
order: 1
tags: ["off-season"]
---

# Background Information

Welcome to one of my "suites"! These suites are me practicing some skills for CTFs or just fooling around. This suite is focused on android reverse engineering. I'll be using OWASP android app samples, picoctf challenges, some hextree.io (maybe) and a google beginner's quest CTF challenge.

## OWASP
#### Android UnCrackable L1 

To start, let's look at basic functionality. 

This app is pretty simple. It prompts for a "secret string" and you provide it, then it checks whether it is correct or not.

Let's load up JADX (JAVA Decompiler) and analyze the source code to see under the hood of this application.

Upon some searching we find some source code that looks like our app

```java
public class MainActivity extends Activity {
    private void a(String str) {
        AlertDialog create = new AlertDialog.Builder(this).create();
        create.setTitle(str);
        create.setMessage("This is unacceptable. The app is now going to exit.");
        create.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable1.MainActivity.1
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialogInterface, int i) {
                System.exit(0);
            }
        });
        create.setCancelable(false);
        create.show();
    }

    @Override // android.app.Activity
    protected void onCreate(Bundle bundle) {
        if (c.a() || c.b() || c.c()) {
            a("Root detected!");
        }
        if (b.a(getApplicationContext())) {
            a("App is debuggable!");
        }
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
    }

    public void verify(View view) {
        String str;
        String obj = ((EditText) findViewById(R.id.edit_text)).getText().toString();
        AlertDialog create = new AlertDialog.Builder(this).create();
        if (a.a(obj)) {
            create.setTitle("Success!");
            str = "This is the correct secret.";
        } else {
            create.setTitle("Nope...");
            str = "That's not it. Try again.";
        }
        create.setMessage(str);
        create.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable1.MainActivity.2
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialogInterface, int i) {
                dialogInterface.dismiss();
            }
        });
        create.show();
    }
}
```

So what we can analyze is that this is the basic functionality of the android application. It sets up all the frontend and actions in the application. Let's try to see how we can get into the `"Success!"` path.

```java
String obj = ((EditText) findViewById(R.id.edit_text)).getText().toString();

if (a.a(obj)) {
            create.setTitle("Success!");
            str = "This is the correct secret.";
}
```

It seems that an `a` object and `a` method is called with the parameter that is our input. Let's try to find this `a` object.

```java
public class a {
    public static boolean a(String str) {
        byte[] bArr;
        byte[] bArr2 = new byte[0];
        try {
            bArr = sg.vantagepoint.a.a.a(b("8d127684cbc37c17616d806cf50473cc"), Base64.decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=", 0));
        } catch (Exception e) {
            Log.d("CodeCheck", "AES error:" + e.getMessage());
            bArr = bArr2;
        }
        return str.equals(new String(bArr));
    }

    public static byte[] b(String str) {
        int length = str.length();
        byte[] bArr = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            bArr[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        }
        return bArr;
    }
}
```
```java
public class a {
    public static byte[] a(byte[] bArr, byte[] bArr2) {
        SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES/ECB/PKCS7Padding");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(2, secretKeySpec);
        return cipher.doFinal(bArr2);
    }
}
```
Wow. Lot to unpack here. But the gist of this is that the program will try to decrypt this hardcoded ciphertext with a hardcoded key which we know because of the AES error. We can also deduce that the AES used is ECB due to the other a object in a different file found.

Let's write a solve script that will decrypt the ciphertext with the hardcoded key we found.

```python
from Crypto.Cipher import AES
import base64
import binascii

ciphertext_base64 = "5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc="  
key_hex = "8d127684cbc37c17616d806cf50473cc" 

key_hash = binascii.unhexlify(key_hex)

ciphertext_bytes = base64.b64decode(ciphertext_base64)


cipher = AES.new(key_hash, AES.MODE_ECB)

decrypted = cipher.decrypt(ciphertext_bytes)

print(decrypted.decode('utf-8'))
```

We get our password: `I want to believe`. We can check this by emulating the android application.

![Image of exploit success](/img/writeups/2024/android-suite/OWASP_level1.png)

## picoCTF

#### droids 3

