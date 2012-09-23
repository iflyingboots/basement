# -*- coding: utf-8 -*-
import hashlib
import random
import string

def encrypt_password(pwd, salt=''):
    return hashlib.md5(pwd + salt).hexdigest()

def get_salt(digit=8):
    return ''.join(random.sample(string.ascii_letters + string.digits, digit))