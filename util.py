# -*- coding: utf-8 -*-
import hashlib
import random
import string
import re

def encrypt_password(pwd, salt=''):
    return hashlib.md5(pwd + salt).hexdigest()

def get_salt(digit=8):
    return ''.join(random.sample(string.ascii_letters + string.digits, digit))

def browser(request):
    ua = request.headers['User-Agent']
    if re.search('iPhone|iPod|Android|Opera Mini|UCWEB|IEMobile', ua):
        return 'mobile'
    return 'web'