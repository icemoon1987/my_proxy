#!/usr/bin/env python
# -*- coding: utf-8 -*-

######################################################
#
# File Name:  config.py
#
# Function:   Client side proxy config file.
#
# Usage:  import config
#
# Author: panwenhai
#
# Create Time:    2016-08-11 13:39:30
#
######################################################

LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 8087

DEBUG_SWITCH = False

AUTORANGE_MAXSIZE = 1048576
hosts = ".youtube.com|.atm.youku.com|.googlevideo.com|av.vimeo.com|smile-*.nicovideo.jp|video.*.fbcdn.net|s*.last.fm|x*.last.fm|.xvideos.com|.phncdn.com|.edgecastcdn.net"

#threads = 2
#maxsize = 1048576
#waitsize = 524288
#bufsize = 8192

AUTORANGE_HOSTS      = tuple(hosts.split('|'))
AUTORANGE_HOSTS_TAIL = tuple(x.rpartition('*')[2] for x in AUTORANGE_HOSTS)

PROXY_SERVER = "http://www.icemoon1987.com/"
#PROXY_SERVER = "http://127.0.0.1:8808"

