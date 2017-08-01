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

# proxy监听IP和端口，如果需要除本机以外机器通过此proxy上网，需要绑定为机器网卡外部地址
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 8087

# Debug开关，影响日志输出
DEBUG_SWITCH = False

# 流媒体一次接收数据块最大字节数，一般不需要修改
AUTORANGE_MAXSIZE = 1048576

# 视频源hosts，一般不需要修改
hosts = ".youtube.com|.atm.youku.com|.googlevideo.com|av.vimeo.com|smile-*.nicovideo.jp|video.*.fbcdn.net|s*.last.fm|x*.last.fm|.xvideos.com|.phncdn.com|.edgecastcdn.net"

# 线程数，默认即可
#threads = 2

# 发送数据分块最大长度，默认即可
#maxsize = 1048576

# 接收数据分块最大长度，默认即可
#waitsize = 524288

# 缓冲区大小，默认即可
#bufsize = 8192

# 视频流媒体url配置，一般不需要修改
AUTORANGE_HOSTS      = tuple(hosts.split('|'))
AUTORANGE_HOSTS_TAIL = tuple(x.rpartition('*')[2] for x in AUTORANGE_HOSTS)

# proxy的server端地址
PROXY_SERVER = "http://www.icemoon1987.com/"
#PROXY_SERVER = "http://127.0.0.1:8808"

