#!/usr/bin/env python
# -*- coding: utf-8 -*-
import MySQLdb
class DB():
    conn = None
    def connect(self):
        self.conn = MySQLdb.connect(
            host=mysql_host,
            user=mysql_username,
            passwd=mysql_password,
            db=mysql_database,
            charset="utf8"
        )

    def query(self, sql):
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql)
        except Exception,e:
            print 'query error', e
            self.connect()
            cursor = self.conn.cursor()
            cursor.execute(sql)
            self.conn.cursor()
        return cursor

    def commit(self):
        self.conn.commit()