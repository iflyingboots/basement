#!/usr/bin/env python
# -*- coding: utf-8 -*-
import MySQLdb
import time
from config import *
from cities import *
from db import DB

QNA_ID = 300
SHARE_ID = 301

db = DB()

def re_connect():
    db = MySQLdb.connect(
    host=mysql_host,
    user=mysql_username,
    db=mysql_database,
    charset="utf8"
    )
    return db, db.cursor()

# detect QNA node
def qna_detect(title):
    question_marks = set([u'?', u'？'])
    questions = set([u'为什么', u'如何'])
    for i in questions:
        if title.find(i) > -1:
            return True
    return title.strip()[-1] in question_marks or title.strip()[0] == u'求'

#detect share node
def share_detect(title):
    share_marks = set([u'发现', u'分享', u'推荐', u'试用'])
    return any([i for i in share_marks if title.find(i) > -1])

def city_detect(title):
    nodes = set()
    CITIES = get_blocks()
    for city, node_id in CITIES.items():
        if title.find(city) > -1:
            nodes.add(node_id)
    return nodes

def insert_nodes(topic_id, nodes):
    for node_id in nodes:
        try:
            db.query(
                'INSERT INTO topics_nodes(topic_id, node_id) VALUES(%s,%s)'
                % (topic_id, node_id)
            )
            db.commit()
        except Exception, e:
            print 'insert error', e

def delete_nodes(topic_id):
    try:
        db.query('DELETE FROM topics_nodes WHERE topic_id = %s' % topic_id)
    except:
        pass

def overall_detect(topic_id, title):
    nodes = set()
    if qna_detect(title):
        nodes.add(QNA_ID)
    if share_detect(title):
        nodes.add(SHARE_ID)
    cities = city_detect(title)
    nodes = nodes.union(cities)
    insert_nodes(topic_id, nodes)

# if __name__ == '__main__':
#     print qna_detect(u'听说国内apple实体店不给保修国外购买的apple产品？')
#     print share_detect(u'求推荐一个很棒的音乐网站')
#     print city_detect(u'北京哪有好吃的啊？')