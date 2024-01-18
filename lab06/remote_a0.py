#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50690)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

json_send({
    "command": "hashpump",
    "mac": "fd43aad042834cfb5d4e21b5bf1b419c5304fb6bc8943275b3cf6e7ea4d0aee4",
    "data": b"command=hello&arg=world".hex(),
    "append": b"&command=flag".hex()
})

print(json_recv())
