#!/usr/bin/env python
# -*- coding: utf-8 -*-
mysql_host = '127.0.0.1'
mysql_database = 'basement'
mysql_username = 'root'
mysql_password = ''
SQLALCHEMY_DATABASE_URI = 'mysql://%s:%s@%s/%s?charset=utf8' % (
	mysql_username, mysql_password, mysql_host, mysql_database)

SECRET_KEY = '\xb9\xed|\xad<\x9fbx\x93\xf7^l\xee\xf6@M\xa1k\x86\x12\x18\xf3>\x0e'
CSRF_ENABLED = True
DEBUG = True