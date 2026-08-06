from base64 import b64encode
from hashlib import pbkdf2_hmac, sha512
import bcrypt
import grp
import os
import pwd
import secrets

def lookup_passwd(pw_file):
    # reuse existing password
    if os.path.exists(pw_file):
        with open(pw_file, "r") as handle:
            return handle.read().rstrip()

    # create new password
    pw = secrets.token_urlsafe(16)
    with open(pw_file, "w") as handle:
        handle.write(pw)

    # set ownership for new file
    uid = pwd.getpwnam("owntracks").pw_uid
    gid = grp.getgrnam("www-data").gr_gid
    os.chown(pw_file, uid, gid)

    return pw

def mosquitto_passwd(passwd):
    iterations = 101
    salt = secrets.token_bytes(12)
    dk = pbkdf2_hmac('sha512', bytes(passwd, 'utf-8'), salt, iterations)
    salt_str = b64encode(salt).decode()
    dk_str = b64encode(dk).decode()
    return f"$7${iterations}${salt_str}${dk_str}"

def nginx_passwd(passwd):
    salt = bcrypt.gensalt(rounds=12)
    hashed_bytes = bcrypt.hashpw(passwd.encode('utf-8'), salt)
    return hashed_bytes.decode('utf-8')

def user_passwd(user, directory):
    if "password" not in user:
        pw_file = os.path.join(directory, user["username"] + ".pw")
        user["password"] = lookup_passwd(pw_file)
    return user

def user_passwds(users, directory):
    newusers = []
    for user in users:
        user_passwd(user, directory)
        newusers.append(user)
    return newusers

class FilterModule(object):
    def filters(self):
        return {
                'lookup_passwd': lookup_passwd,
                'mosquitto_passwd': mosquitto_passwd,
                'nginx_passwd': nginx_passwd,
                'user_passwd': user_passwd,
                'user_passwds': user_passwds}

