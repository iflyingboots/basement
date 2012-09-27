#!/usr/bin/env python
# -*- coding: utf-8 -*-
import MySQLdb
from smallseg import SEG
from config import *
seg = SEG()

QNA_ID = 300
SHARE_ID = 301

db = MySQLdb.connect(
    host=mysql_host,
    user=mysql_username,
    db=mysql_database,
    charset="utf8"
)

c = db.cursor()

# detect QNA node
def qna_detect(title):
    question_marks = set([u'?', u'？'])
    return title.strip()[-1] in question_marks or title.strip()[0] == u'求'

def share_detect(title):
    share_marks = set([u'发现', u'分享', u'推荐', u'试用'])
    no_words = set(u'求')
    seg_res = set(seg.cut(title.strip()))
    return any(i not in no_words and i in share_marks for i in seg_res)

def city_detect(title):
    nodes = set()
    for city, node_id in CITIES.items():
        if title.find(city) >= 0:
            nodes.add(node_id)
    return nodes

def insert_nodes(topic_id, nodes):
    for node_id in nodes:
        try:
            c.execute(
                'INSERT INTO topics_nodes(topic_id, node_id) VALUES(%s,%s)'
                % (topic_id, node_id)
            )
        except Exception, e:
            print e
    db.commit()

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