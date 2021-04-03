#!/usr/bin/env python3

import sys
import os
import base64
import getpass
import argparse

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


##########
# CONFIG #
##########

# Where picop password files will be stored.
STORE = os.path.join(os.environ['HOME'], ".picop")

# What the salt filename will be called.
SALT_FILENAME = ".salt"

# What the validator filename will be called.
VAL_FILENAME = ".val"

# What the contents of the validator file will be.
VAL_CONTENTS = "picop_validator".encode("utf-8")


###########
# HELPERS #
###########

# Picop validation errors.
class PicopError(Exception):
    pass

# Registers functions as picop commands, and includes exception handling.
CHOICES = dict()
def picop_cmd(name):
    def picop_decorate(func):
        def picop_handle(args):
            try:
                func(args)
            except PicopError as e:
                sys.stderr.write("Error: {}\n".format(e.args[0]))
        CHOICES[name] = picop_handle
        return picop_handle
    return picop_decorate

# Gets the password storage path, and if it doesn't exist, creates one.
def get_store_dir():
    if not os.path.exists(STORE):
        os.makedirs(STORE)
    return STORE

# Gets the picop salt path.
def get_salt_path():
    salt_path = os.path.join(get_store_dir(), SALT_FILENAME)
    if not os.path.exists(salt_path):
        raise PicopError("No salt found! Generate a salt first.")
    return salt_path

# Gets the path for the password token
def get_token_path(name, should_exist=None):
    if not name:
        raise PicopError("No name specified.")
    filename = os.path.join(get_store_dir(), name)
    
    if should_exist is not None:
        ex = os.path.exists(filename)
        if ex and not should_exist:
            raise PicopError("An existing password file is stored under the same name. "
                             "Delete it first.")
        if not ex and should_exist:
            raise PicopError("No password file under the name '{}'.".format(name))

    return filename



# Gets the picop salt.
def get_salt():
    salt_path = get_salt_path()
    with open(salt_path, "rb") as f:
        res = f.read()
    return res

# Validates a picop key.
def validate_key(key):
    val_path = os.path.join(get_store_dir(), VAL_FILENAME)
    if not os.path.exists(val_path):
        raise PicopError("No validation files! Have you initialised picop?")

    fernet = Fernet(key)

    try:
        with open(val_path, "rb") as f:
            token = f.read()
            if fernet.decrypt(token) != VAL_CONTENTS:
                raise InvalidToken()
    except InvalidToken as e:
        raise PicopError("Key validation failed! Did you type the super password "
                         "correctly?")

# Gets the key derivation function.
def get_kdf(salt):
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)

# Gets the base64 picop key, which is a combination of the salt and the super password.
def get_key():
    salt = get_salt()
    kdf = get_kdf(salt)

    # The super password should only be obtained here
    superpw = getpass.getpass(prompt="Enter super password: ").encode("utf-8")

    key = base64.urlsafe_b64encode(kdf.derive(superpw))
    validate_key(key)

    return key

############
# COMMANDS #
############

@picop_cmd("init")
def picop_init(args):
    salt_path = os.path.join(get_store_dir(), SALT_FILENAME)
    val_path = os.path.join(get_store_dir(), VAL_FILENAME)
    if os.path.exists(salt_path):
        raise PicopError("Salt already exists!")
    if os.path.exists(val_path):
        raise PicopError("Validator file already exists!")

    superpw1 = getpass.getpass(prompt="Enter new super password: ")
    superpw2 = getpass.getpass(prompt="Re-enter new super password: ")

    if superpw1 != superpw2:
        raise PicopError("Passwords do not match!")

    # Generate and write salt
    new_salt = os.urandom(16)

    # Generate key
    kdf = get_kdf(new_salt)
    key = base64.urlsafe_b64encode(kdf.derive(superpw1.encode("utf-8")))
    fernet = Fernet(key)

    with open(salt_path, "wb") as f:
        f.write(new_salt)
    print("Salt successfully written to store.")
    with open(val_path, "wb") as f:
        f.write(fernet.encrypt(VAL_CONTENTS))
    print("Validator successfully written to store.")


@picop_cmd("add")
def picop_add(args):
    name = args.name
    filepath = get_token_path(name, False)

    if os.path.exists(filepath):
        raise PicopError("An existing password file is stored under the same name. "
                         "Delete it first.")

    key = get_key()

    newp1 = getpass.getpass(prompt="Enter new password: ")
    newp2 = getpass.getpass(prompt="Re-enter new password: ")

    if newp1 != newp2:
        raise PicopError("Passwords do not match!")
    
    fernet = Fernet(key)
    token = fernet.encrypt(newp1.encode("utf-8"))

    with open(filepath, "wb") as f:
        f.write(token)
    
    print("Password with name {} successfully added".format(name))

@picop_cmd("get")
def picop_get(args):
    name = args.name
    filepath = get_token_path(name, True)

    if not os.path.exists(filepath):
        raise PicopError("No password file under the name '{}'.".format(name))

    key = get_key()

    fernet = Fernet(key)
    with open(filepath, "rb") as f:
        token = f.read()

    print(fernet.decrypt(token).decode("utf-8"))

@picop_cmd("remove")
def picop_remove(args):
    name = args.name
    filepath = get_token_path(name, True)
    
    print("Are you sure you want to delete this?")
    confirmation = input("Re-enter the name of the password you are deleting: ")
    if confirmation != args.name:
        raise PicopError("Names did not match")

    os.remove(filepath)
    print("Removed {}.".format(name))

@picop_cmd("list")
def picop_list(args):
    store_dir = get_store_dir()
    names = []
    for entry in os.scandir(store_dir):
        if entry.is_file() and not entry.name.startswith("."):
            names.append(entry.name)

    names.sort()
    print("Stored passwords:")
    for name in names:
        print("- {}".format(name))


########
# MAIN #
########

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", help="the command to run", 
                        choices=CHOICES.keys())
    parser.add_argument("-n", "--name", help="the name associated with the password", 
                        default="", )

    args = parser.parse_args()

    CHOICES[args.command](args)
