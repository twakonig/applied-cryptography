#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

tn_m0 = telnetlib.Telnet("aclabs.ethz.ch", 50600)
tn_a0 = telnetlib.Telnet("aclabs.ethz.ch", 50690)


def readline(tn):
    return tn.read_until(b"\n")

def json_recv(tn):
    line = readline(tn)
    return json.loads(line.decode())

def json_send(req, tn):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")


def main():

    # request token from m0
    request = {
        "command": "token"
    }
    json_send(request, tn_m0)
    response = json_recv(tn_m0)
    print(response)
    token_hello = response["token"]
    command_string = token_hello["command_string"]
    append_string = b"&command=flag".hex()
    mac = token_hello["mac"]

    # length extension attack via a0
    attack = {
        "command": "hashpump",
        "mac": mac,
        "data": bytes.fromhex(command_string).decode(),
        "append": "&command=flag"
    }
    json_send(attack, tn_a0)
    response = json_recv(tn_a0)
    new_mac = response["new_hash"]
    print(response)

    # craft new token
    token_crafted = {
        "command_string": response["new_data"],
        "mac": new_mac
    }

    # send token command to m0
    request = {
        "command": "token_command",
        "token": token_crafted
    }
    json_send(request, tn_m0)
    response = json_recv(tn_m0)
    print(response)

    return


if __name__ == "__main__":
   main()