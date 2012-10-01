#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

DOMAIN = 'http://test.airpost.in'
mysql_host = '127.0.0.1'
mysql_database = 'basement'
mysql_username = 'root'
mysql_password = ''
SQLALCHEMY_DATABASE_URI = 'mysql://%s:%s@%s/%s?charset=utf8' % (
	mysql_username, mysql_password, mysql_host, mysql_database)
SECRET_KEY = '\xb9\xed|\xad<\x9fbx\x93\xf7^l\xee\xf6@M\xa1k\x86\x12\x18\xf3>\x0e'
CSRF_ENABLED = True
DEBUG = True
UPLOADS_DEFAULT_DEST = os.path.join(os.getcwd(), 'basement/static/uploads')
UPLOADS_DEFAULT_URL = DOMAIN + '/uploads/'
UPLOADED_AVATARS_ALLOW = set(['jpg', 'gif', 'jpeg', 'png'])

CACHE_TYPE = 'simple'
