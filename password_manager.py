import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys
from Crypto.Protocol.KDF import scrypt
import string
import random
from base64 import b64encode, b64decode


def init():
    master_password = sys.argv[2]
    file = open("data.json", "w")

    salt = get_random_bytes(32)
    key = scrypt(master_password, salt, key_len=32, N=2 ** 17, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM)

    test_string = ''.join(random.choices(string.ascii_lowercase + string.ascii_uppercase + string.digits, k=8))
    # print(test_string)
    ciphertext, tag = cipher.encrypt_and_digest(test_string.encode('utf-8'))

    entry_init = {
        "sample":
            {
                "salt": b64encode(salt).decode('utf-8'),
                "nonce": b64encode(cipher.nonce).decode('utf-8'),
                "ciphertext": b64encode(ciphertext).decode('utf-8'),
                "tag": b64encode(tag).decode('utf-8'),
            },
        "entries": []
    }

    json.dump(entry_init, file, indent=4)
    file.close()
    print("Password manager initialized.")


def get(opt_address=''):
    # Checking master password
    master_password = sys.argv[2]
    try:
        file = open('data.json', 'r')
        data = json.load(file)
    except FileNotFoundError:
        print("Please initialize the password manager before using the get command.")
        sys.exit()

    if opt_address == '':
        address = sys.argv[3]
    else:
        address = opt_address

    found = False
    found_idx = None

    for idx, entry in enumerate(data["entries"]):
        arg_data_salt = b64decode(entry["arg_data_salt"].encode('utf-8'))
        arg_data_key = scrypt(master_password, arg_data_salt, key_len=32, N=2 ** 17, r=8, p=1)
        arg_data_nonce = b64decode(entry["arg_data_nonce"].encode('utf-8'))
        arg_data_cipher = AES.new(arg_data_key, AES.MODE_GCM, nonce=arg_data_nonce)

        try:
            ciphertext = b64decode(entry["arg_data_ct"].encode('utf-8'))
            tag = b64decode(entry["arg_data_tag"].encode('utf-8'))
            decoding = arg_data_cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
            # print(decoding)
            adr = decoding.split(" ")[0]

            if adr == address:
                if opt_address == '':
                    print(f"Password for {address} is : {decoding.split(' ')[1]}")
                found = True
                found_idx = idx
                # sys.exit()

        except ValueError:
            print("Master password incorrect or integrity check failed.")
            sys.exit()
    if found:
        file.close()
        return True, found_idx
    else:
        if opt_address == '':
            print(f"The password for {address} isn't stored.")
        file.close()
        return False, found_idx


def put():
    # Checking master password
    master_password = sys.argv[2]
    try:
        file = open('data.json', 'r')
        data = json.load(file)
    except FileNotFoundError:
        print("Please initialize the password manager before using the put command.")
        sys.exit()

    salt = b64decode(data["sample"]["salt"].encode('utf-8'))
    key = scrypt(master_password, salt, key_len=32, N=2 ** 17, r=8, p=1)
    nonce = b64decode(data["sample"]["nonce"].encode('utf-8'))
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        ciphertext = b64decode(data["sample"]["ciphertext"].encode('utf-8'))
        tag = b64decode(data["sample"]["tag"].encode('utf-8'))
        decoding = cipher.decrypt_and_verify(ciphertext, tag)
        # print(decoding.decode('utf-8'))
    except ValueError:
        print("Master password incorrect or integrity check failed.")
        sys.exit()
    file.close()

    # file = open('data.json', 'w')
    # data["entries"] = []
    # json.dump(data, file, indent=4)
    # file.close()

    # Put new address and password
    file = open('data.json', 'r')
    data = json.load(file)
    file.close()

    # file = open("data.json", "w")

    address = sys.argv[3]
    password = sys.argv[4]

    address_present, index = get(opt_address=address)

    file = open("data.json", "w")

    arg_data = address + " " + password

    arg_data_salt = get_random_bytes(32)
    arg_data_key = scrypt(master_password, arg_data_salt, key_len=32, N=2 ** 17, r=8, p=1)
    arg_data_cipher = AES.new(arg_data_key, AES.MODE_GCM)

    arg_data_ct, arg_data_tag = arg_data_cipher.encrypt_and_digest(arg_data.encode('utf-8'))

    entry = {
        "arg_data_salt": b64encode(arg_data_salt).decode('utf-8'),
        "arg_data_nonce": b64encode(arg_data_cipher.nonce).decode('utf-8'),
        "arg_data_ct": b64encode(arg_data_ct).decode('utf-8'),
        "arg_data_tag": b64encode(arg_data_tag).decode('utf-8'),
    }

    if address_present:
        data["entries"][index] = entry
    else:
        data["entries"].append(entry)
    json.dump(data, file, indent=4)
    file.close()
    print(f"Stored password for {address}.")


match sys.argv[1]:
    case "init":
        init()

    case "put":
        put()

    case "get":
        get()

    case _:
        print("Please enter a valid command.")
