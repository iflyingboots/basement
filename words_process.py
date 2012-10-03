#!/usr/bin/env python
# -*- coding: utf-8 -*-
from datetime import datetime
from smallseg import SEG
from db import DB
import re
import redis
r = redis.StrictRedis(host='localhost', port=6379, db=1)

seg = SEG()
stopwords = set([i.decode('utf-8') for i in open('stopwords.dic', 'r').read().split()])

THRESHOLD = 2

def tidy(html):
	return re.sub(ur'[\.,!@#$%^&\*\(\)，。（）+<>=\?？]', ' ', html)

def cut_words(html):
	html = tidy(html)
	res = {}
	for i in seg.cut(html):
		if i not in stopwords:
			res[i] = 1
	return res

def words_freq(sentence, topic_id):
	sentence = tidy(sentence)
	for i in seg.cut(sentence):
		if i not in stopwords:
			cnt = '%s:c' % i
			topic = '%s:t' % i
			r.incr(cnt)
			r.sadd(topic, topic_id)
			count = int(r.get(cnt))
			topics = r.smembers(topic)
			if count = THRESHOLD:
				add_node(i)
				modify_topics(topics, i)

def add_node(node):
	try:
		db.query('INSERT INTO nodes(value, url, active, ctime, topic_num) VALUES("%s", "%s", 1, "%s", 1)' % (value, value, int(datetime.now())))
	except Exception,e:
		print e
	db.commit()

def modify_topics(topics, node_id):
	for topic_id in topics:
		try:
			db.query('INSERT INTO topics_nodes(topic_id, node_id) VALUES(%s,%s)'
                % (int(topic_id), node_id))
		except Exception,e:
			print e
	db.commit()

def main():
    t = u'''
    Microsoft”一词由“MICROcomputer（微型计算机）”和“SOFTware（软件）”两部分组成。我了个去@sutar #TEST 什么心态
    '''
    t = u'《SQL反模式》是一本书。TODO：修复这个BUG'
    t = u'简单的读取数据业务采用 MongoDB 还是 MySQL?'
    words_freq(t, 50)

# if __name__ == '__main__':
#     main()