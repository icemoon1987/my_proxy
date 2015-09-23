#!/usr/bin/env python
# coding:utf-8

__version__ = '1.0.0'
__bufsize__ = 1024*1024

import sys
import os
import config as cfg
import logging

try:
	# Use gevent by default
	import gevent
	import gevent.queue
	import gevent.monkey
	import gevent.coros
	import gevent.server
	import gevent.pool
	import gevent.event
	import gevent.timeout
	gevent.monkey.patch_all(dns=gevent.version_info[0]>=1)
except ImportError:

	# if gevent is not installed, use Queue, thread, SocketServer instead

	print 'WARNING: python-gevent not installed. Use SocketServer instead'

	import Queue
	import thread
	import threading
	import SocketServer

	def GeventImport(name):
		import sys
		sys.modules[name] = type(sys)(name)
		return sys.modules[name]
	def GeventSpawn(target, *args, **kwargs):
		return thread.start_new_thread(target, args, kwargs)
	def GeventSpawnLater(seconds, target, *args, **kwargs):
		def wrap(*args, **kwargs):
			import time
			time.sleep(seconds)
			return target(*args, **kwargs)
		return thread.start_new_thread(wrap, args, kwargs)
	class GeventServerStreamServer(SocketServer.ThreadingTCPServer):
		allow_reuse_address = True
		def finish_request(self, request, client_address):
			self.RequestHandlerClass(request, client_address)
	class GeventServerDatagramServer(SocketServer.ThreadingUDPServer):
		allow_reuse_address = True
		def __init__(self, server_address, *args, **kwargs):
			SocketServer.ThreadingUDPServer.__init__(self, server_address, GeventServerDatagramServer.RequestHandlerClass, *args, **kwargs)
			self._writelock = threading.Semaphore()
		def sendto(self, *args):
			self._writelock.acquire()
			try:
				self.socket.sendto(*args)
			finally:
				self._writelock.release()
		@staticmethod
		def RequestHandlerClass((data, server_socket), client_addr, server):
			return server.handle(data, client_addr)
		def handle(self, data, address):
			raise NotImplemented()
	class GeventPoolPool(object):
		def __init__(self, size):
			self._lock = threading.Semaphore(size)
		def __target_wrapper(self, target, args, kwargs):
			t = threading.Thread(target=target, args=args, kwargs=kwargs)
			try:
				t.start()
				t.join()
			except Exception as e:
				print 'threading.Thread target=%r error:%s' % (target, e)
			finally:
				self._lock.release()
		def spawn(self, target, *args, **kwargs):
			self._lock.acquire()
			return thread.start_new_thread(self.__target_wrapper, (target, args, kwargs))

	gevent        = GeventImport('gevent')
	gevent.queue  = GeventImport('gevent.queue')
	gevent.coros  = GeventImport('gevent.coros')
	gevent.server = GeventImport('gevent.server')
	gevent.pool   = GeventImport('gevent.pool')

	gevent.queue.Queue           = Queue.Queue
	gevent.queue.Empty           = Queue.Empty
	gevent.coros.Semaphore       = threading.Semaphore
	gevent.getcurrent            = threading.currentThread
	gevent.spawn                 = GeventSpawn
	gevent.spawn_later           = GeventSpawnLater
	gevent.server.StreamServer   = GeventServerStreamServer
	gevent.server.DatagramServer = GeventServerDatagramServer
	gevent.pool.Pool             = GeventPoolPool

	del GeventImport, GeventSpawn, GeventSpawnLater, GeventServerStreamServer, GeventServerDatagramServer, GeventPoolPool

import collections
import errno
import time
import cStringIO
import struct
import re
import zlib
import random
import base64
import urlparse
import socket
import ssl
import select
import traceback
import hashlib
import fnmatch
import ConfigParser
import httplib
import urllib2
import heapq
import threading
try:
	import ctypes
except ImportError:
	ctypes = None
try:
	import OpenSSL
except ImportError:
	OpenSSL = None

from Http import Http

class proxy_client(object):

	def __init__(self, listen_ip, listen_port):

		self.listen_ip = listen_ip
		self.listen_port = listen_port
		self.http_handler = Http()

		if cfg.DEBUG_SWITCH:
			log_level = logging.DEBUG
		else:
			log_level = logging.INFO

		logging.basicConfig(format="%(levelname)s:\t%(asctime)s\t%(name)s\t%(message)s", level = log_level)
		self.logger = logging.getLogger("proxy_client")

		return

	def send_proxy_request(self, proxy_request, proxy_server):

		response = self.http_handler.request(proxy_request['method'], proxy_server, proxy_request['proxy_payload'], {'Content-Length':proxy_request['proxy_payload_len']}, crlf=proxy_request['need_crlf'])

		response.app_status = response.status

		print "status: " + str(response.status)
		print dir(response)
		print response.msg
		print response.reason
		print response.getheaders()
		print response.read()

		data = response.read(4)

		return

		if len(data) < 4:
			response.status = 502
			response.fp = cStringIO.StringIO('connection aborted. too short leadtype data=%r' % data)
			return response

		response.status, headers_length = struct.unpack('!hh', data)

		data = response.read(headers_length)

		if len(data) < headers_length:
			response.status = 502
			response.fp = cStringIO.StringIO('connection aborted. too short headers data=%r' % data)
			return response

		response.msg = httplib.HTTPMessage(cStringIO.StringIO(zlib.decompress(data, -15)))

		return response


	def compose_proxy_request(self, user_request):

		proxy_request = {}

		if 'Range' in user_request['headers']:
			m = re.search('bytes=(\d+)-', user_request['headers']['Range'])
			start = int(m.group(1) if m else 0)
			user_request['headers']['Range'] = 'bytes=%d-%d' % (start, start + cfg.AUTORANGE_MAXSIZE-1)
			self.logger.info('autorange range=%r match url=%r', user_request['headers']['Range'], user_request['path'])

		elif user_request['host'].endswith(cfg.AUTORANGE_HOSTS_TAIL):
			try:
				pattern = (p for p in cfg.AUTORANGE_HOSTS if user_request['host'].endswith(p) or fnmatch.fnmatch(user_request['host'], p)).next()
				self.logger.debug('autorange pattern=%r match url=%r', pattern, user_request['path'])
				m = re.search('bytes=(\d+)-', user_request['headers'].get('Range', ''))
				start = int(m.group(1) if m else 0)
				user_request['headers']['Range'] = 'bytes=%d-%d' % (start, start + cfg.AUTORANGE_MAXSIZE-1)
			except StopIteration:
				pass
				
		# Compress the payload if necessary
		if user_request['payload']:
			if len(user_request['payload']) < 10 * 1024 * 1024 and 'Content-Encoding' not in user_request['headers']:
				zpayload = zlib.compress(user_request['payload'])[2:-4]
				if len(zpayload) < len(user_request['payload']):
					user_request['payload'] = zpayload
					user_request['headers']['Content-Encoding'] = 'deflate'
			user_request['headers']['Content-Length'] = str(len(user_request['payload']))

		# Warp the user request into proxy request
		skip_headers = self.http_handler.skip_headers
		metadata = 'User-Method:%s\nUser-Url:%s\n%s\n' % (user_request['method'], user_request['path'], '\n'.join('%s:%s'%(k,v) for k,v in user_request['headers'].iteritems() if k not in skip_headers))
		metadata = zlib.compress(metadata)[2:-4]
		proxy_payload = '%s%s%s' % (struct.pack('!h', len(metadata)), metadata, user_request['payload'])
		#proxy_payload = metadata

		need_crlf = 0

		proxy_request['method'] = "POST"
		proxy_request['proxy_payload'] = proxy_payload
		proxy_request['proxy_payload_len'] = len(proxy_payload)
		proxy_request['need_crlf'] = need_crlf

		return proxy_request


	def proxy_handler(self, sock, address):

		#try:
		# Receive and parse user requests
		rfile = sock.makefile('rb', __bufsize__)
		user_request = self.http_handler.parse_request(rfile)

		# Compose proxy requests
		proxy_request = self.compose_proxy_request(user_request)

		# Send proxy request to server, and get proxy response
		proxy_response = self.send_proxy_request(proxy_request, cfg.PROXY_SERVER)

		# Get proxy respons from server

		# Parse proxy respons

		# Send respons back to user
		#user_addr, user_port = address

		#except Exception, ex:
			#self.logger.warning(ex.__str__())
			#return

		return


	def run(self):

		self.logger.info("proxy_client init finish.")
		server = gevent.server.StreamServer((self.listen_ip, self.listen_port), self.proxy_handler)
		self.logger.info("proxy_client listen on: %s:%d" % (self.listen_ip, self.listen_port) )

		server.serve_forever()

		return


if __name__ == '__main__':
	try:
		client = proxy_client(cfg.LISTEN_IP, cfg.LISTEN_PORT)
		client.run()
	except KeyboardInterrupt:
		pass
	except Exception, ex:
		print ex.__str__()
