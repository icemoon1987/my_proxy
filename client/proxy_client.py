#!/usr/bin/env python
# -*- coding: utf-8 -*-

######################################################
#
# File Name:    proxy_client.py
#
# Function:     The client side of the proxy. Pack user request in a post request and sent it to server side.
#               This client servers as a server for user browser.
#
# Usage:  python proxy_client.py
#
# Author: panwenhai
#
# Create Time:    2016-08-11 11:50:33
#
######################################################

__version__ = '1.0.0'

# Socket buffer size in bytes
__bufsize__ = 1024*1024

import sys
import os
import config as cfg
import logging
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

from Http import Http
from CertUtil import CertUtil

# Use gevent by default. If gevent is not installed, use Queue, thread, SocketServer instead.
try:
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
    print 'WARNING: python-gevent not installed. Use SocketServer instead'

    import Queue
    import thread
    import threading
    import SocketServer

    # Warp all gevent functions
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

##
# @brief    Main class of client-side proxy
class proxy_client(object):

    ##
    # @brief    initilize params and logger
    #
    # @param    listen_ip
    # @param    listen_port
    #
    # @return
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

	if 'x-status' in response.msg:
	    response.status = int(response.msg['x-status'])
	    del response.msg['x-status']
	if 'status' in response.msg:
	    response.status = int(response.msg['status'])
	    del response['status']

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
	need_crlf = 0
	proxy_request['method'] = "POST"
	proxy_request['proxy_payload'] = proxy_payload
	proxy_request['proxy_payload_len'] = len(proxy_payload)
        proxy_request['need_crlf'] = need_crlf

	return proxy_request


    def parse_proxy_response(self, response, sock):
	result = ""
	wfile = sock.makefile('wb', 0)
	if 'Set-Cookie' in response.msg:
	    response.msg['Set-Cookie'] = re.sub(', ([^ =]+(?:=|$))', '\\r\\nSet-Cookie: \\1', response.msg['Set-Cookie'])

	wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'transfer-encoding')))

	while 1:
            data = response.read(8192)
	    if not data:
		break
	    wfile.write(data)

	response.close()

	return result

    def send_proxy_result(self, proxy_result, sock):
        wfile = sock.makefile('wb', 0)
	self.logger.info("proxy_result_len: " + str(len(proxy_result)))
	wfile.write(proxy_result)
	wfile.close()
	sock.close()

	return


    def parse_user_request(self, sock):
	result = {}
	''' parse http parameters '''
	rfile = sock.makefile('rb', __bufsize__)
	method, path, version, headers = self.http_handler.parse_request(rfile)
	''' handle CONNECT requests '''
	__realsock = None
	__realrfile = None

	if method == 'CONNECT':
	    host, _, port = path.rpartition(':')
	    port = int(port)
	    keyfile, certfile = CertUtil.get_cert(host)
	    sock.sendall('HTTP/1.1 200 OK\r\n\r\n')
	    __realsock = sock
	    __realrfile = rfile

	    try:
	        sock = ssl.wrap_socket(__realsock, certfile=certfile, keyfile=keyfile, server_side=True)
	    except Exception as e:
		__realrfile.close()
		__realsock.close()
		return

	    rfile = sock.makefile('rb', __bufsize__)
	    try:
		method, path, version, headers = self.http_handler.parse_request(rfile)
	    except (EOFError, socket.error) as e:
		if e[0] in ('empty line', 10053, errno.EPIPE):
		    return rfile.close()
		raise
	    if path[0] == '/' and host:
		path = 'https://%s%s' % (headers['Host'], path)
	else:
	    host = headers.get('Host', '')
	    if path[0] == '/' and host:
		path = 'http://%s%s' % (host, path)

	content_length = int(headers.get('Content-Length', 0))
	payload = rfile.read(content_length) if content_length else ''
	result["method"] = method
	result["path"] = path
	result["version"] = version
	result["headers"] = headers
	result["host"] = host
	result["content_length"] = content_length
	result["payload"] = payload

	return result


    ##
    # @brief    handler for user browser requests
    #
    # @param    sock: socket for this request
    # @param    address: ip address of this request
    #
    # @return   
    def paasproxy_handler(self, sock, address):

	http = self.http_handler

	# Get user request url and parse it
	rfile = sock.makefile('rb', __bufsize__)
	try:
	    method, path, version, headers = http.parse_request(rfile)
	except (EOFError, socket.error) as e:
	    if e[0] in ('empty line', 10053, errno.EPIPE):
		return rfile.close()
	    raise

	# Uncomment this line if you need to fake browser.
	#headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.99 Safari/537.36'
	remote_addr, remote_port = address
	__realsock = None
	__realrfile = None

	# For CONNECT request, establish a fake connection.
	if method == 'CONNECT':
	    host, _, port = path.rpartition(':')
	    port = int(port)
	    keyfile, certfile = CertUtil.get_cert(host)
	    logging.info('CONNECT %s:%s "%s:%d HTTP/1.1" - -' % (address[0], address[1], host, port))

	    # Tell the user browser, the connection is established.
	    sock.sendall('HTTP/1.1 200 OK\r\n\r\n')
	    __realsock = sock
	    __realrfile = rfile
	    try:
		# Warp the connection with fake certificate
		sock = ssl.wrap_socket(__realsock, certfile=certfile, keyfile=keyfile, server_side=True)
	    except Exception as e:
		logging.exception('ssl.wrap_socket(__realsock=%r) failed: %s', __realsock, e)
	        __realrfile.close()
		__realsock.close()
		return

	    # Get user browser's https request
	    rfile = sock.makefile('rb', __bufsize__)
	    try:
		method, path, version, headers = http.parse_request(rfile)
	    except (EOFError, socket.error) as e:
		if e[0] in ('empty line', 10053, errno.EPIPE):
		    return rfile.close()
		raise

	    if path[0] == '/' and host:
		path = 'https://%s%s' % (headers['Host'], path)


	host = headers.get('Host', '')

	if path[0] == '/' and host:
	    path = 'http://%s%s' % (host, path)
	try:
	    try:
		# Wrap the user browser's request into a POST request, send the POST request to proxy_server
		content_length = int(headers.get('Content-Length', 0))
		payload = rfile.read(content_length) if content_length else ''
		response = self.paas_urlfetch(method, path, headers, payload, cfg.PROXY_SERVER)
		logging.info('%s:%s "PAAS %s %s HTTP/1.1" %s -', remote_addr, remote_port, method, path, response.status)
	    except socket.error as e:
		if e.reason[0] not in (11004, 10051, 10060, 'timed out', 10054):
		    raise
	    except Exception as e:
		logging.exception('error: %s', e)
		raise

	    if response.app_status in (400, 405):
		http.crlf = 0

	    # Get the proxy_server's response, unwarp the content.
	    wfile = sock.makefile('wb', 0)

	    if 'Set-Cookie' in response.msg:
		response.msg['Set-Cookie'] = re.sub(', ([^ =]+(?:=|$))', '\\r\\nSet-Cookie: \\1', response.msg['Set-Cookie'])

	    wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'transfer-encoding')))

	    # Send the real page back to user browser.
	    while 1:
	        data = response.read(8192)
		if not data:
		    break
		wfile.write(data)

	    response.close()

	except socket.error as e:
	    # Connection closed before proxy return
	    if e[0] not in (10053, errno.EPIPE):
		raise

	finally:
	    rfile.close()
	    sock.close()
	    if __realrfile:
		__realrfile.close()
	    if __realsock:
		__realsock.close()

        return


    def paas_urlfetch(self, method, url, headers, payload, fetchserver, **kwargs):
	# deflate = lambda x:zlib.compress(x)[2:-4]
	http = self.http_handler

	if payload:
	    if len(payload) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
		zpayload = zlib.compress(payload)[2:-4]
		if len(zpayload) < len(payload):
		    payload = zpayload
		    headers['Content-Encoding'] = 'deflate'
	    headers['Content-Length'] = str(len(payload))

	skip_headers = http.skip_headers
	metadata = 'User-Method:%s\nUser-Url:%s\n%s\n%s\n' % (method, url, '\n'.join('User-%s:%s'%(k,v) for k,v in kwargs.iteritems() if v), '\n'.join('%s:%s'%(k,v) for k,v in headers.iteritems() if k not in skip_headers))
	metadata = zlib.compress(metadata)[2:-4]
	app_payload = '%s%s%s' % (struct.pack('!h', len(metadata)), metadata, payload)
	response = http.request('POST', fetchserver, app_payload, {'Content-Length':len(app_payload)}, crlf=0)
	response.app_status = response.status
	if 'x-status' in response.msg:
	    response.status = int(response.msg['x-status'])
	    del response.msg['x-status']
	if 'status' in response.msg:
	    response.status = int(response.msg['status'])
	    del response['status']

	return response
	
    ##
    # @brief   start the client and wait for browser requests
    #
    # @return  none 
    def run(self):

        # Check certificate, the certificate will be used to warp https connections
	CertUtil.check_ca()

        # Start a stream server, wait for incoming http requests
	server = gevent.server.StreamServer((self.listen_ip, self.listen_port), self.paasproxy_handler)
	self.logger.info("proxy_client listen on: %s:%d" % (self.listen_ip, self.listen_port) )
	server.serve_forever()

	return


if __name__ == '__main__':
    try:
	client = proxy_client(cfg.LISTEN_IP, cfg.LISTEN_PORT)
	client.run()
    except Exception, ex:
	print ex.__str__()




