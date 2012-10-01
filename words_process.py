#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
from smallseg import SEG
seg = SEG()
stopwords = set([i.decode('utf-8') for i in open('stopwords.dic', 'r').read().split()])

def strap(html):
	print re.sub(ur'[\.,!@#$%^&\*\(\)，。（）+=\?？]', ' ', html)

def main():
    t = u'''
    Microsoft”一词由“MICROcomputer（微型计算机）”和“SOFTware（软件）”两部分组成。我了个去@sutar #TEST 什么心态
    '''
    t = u'《SQL反模式》是一本书。TODO：修复这个BUG'
    for i in  seg.cut(t):
        if i not in stopwords:
            print i

if __name__ == '__main__':
    main()