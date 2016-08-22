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


    ##
    # @brief    Handler for user browser requests
    #           For CONNECT request, this function will handle two requests: the CONNECT request and the following request.
    #           For other request, this function will handle only one request.
    #
    # @param    sock: socket for this request
    # @param    address: (ip address, port) for client
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

	# Change user-agent in header, if you need to fake browser 
	#headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.99 Safari/537.36'
	remote_addr, remote_port = address

        # Socket and rfilt for CONNECT request
	__realsock = None
	__realrfile = None

	# For CONNECT request, establish the connection.
	if method == 'CONNECT':
	    host, _, port = path.rpartition(':')
	    port = int(port)

	    logging.info('%s:%s "CONNECT %s:%d HTTP/1.1" - -' % (address[0], address[1], host, port))

            # Get certificate from target host
	    keyfile, certfile = CertUtil.get_cert(host)

	    # Tell the user browser, the connection is established.
	    sock.sendall('HTTP/1.1 200 OK\r\n\r\n')

            # The response will be send by the socket that sent the CONNECT connect
	    __realsock = sock
	    __realrfile = rfile

	    try:
		# Wrap the connection with target host certificate
		sock = ssl.wrap_socket(__realsock, certfile=certfile, keyfile=keyfile, server_side=True)
	    except Exception as e:
		logging.exception('ssl.wrap_socket(__realsock=%r) failed: %s', __realsock, e)
	        __realrfile.close()
		__realsock.close()
		return

	    # Get user browser's next request
	    rfile = sock.makefile('rb', __bufsize__)
	    try:
		method, path, version, headers = http.parse_request(rfile)
	    except (EOFError, socket.error) as e:
		if e[0] in ('empty line', 10053, errno.EPIPE):
		    return rfile.close()
		raise

            # If the request uses CONNECT, it is a https request
            proto = "https"
        else:
            proto = "http"

	host = headers.get('Host', '')

        # If path is not complete, compose one.
	if path[0] == '/' and host:
	    path = proto + '://%s%s' % (host, path)

	try:
	    try:
	        # Wrap the user browser's request into a POST request, send the POST request to proxy_server
	        # Get the proxy_server's response, unwarp the content.
		content_length = int(headers.get('Content-Length', 0))
		payload = rfile.read(content_length) if content_length else ''
		response = self.paas_urlfetch(method, path, headers, payload, cfg.PROXY_SERVER)
		logging.info('%s:%s "%s %s HTTP/1.1" %s -', remote_addr, remote_port, method, path, response.status)

	    except socket.error as e:
                # TODO: why ignore some exception? These exception will send the response back to user browser
		if e.reason[0] not in (11004, 10051, 10060, 'timed out', 10054):
		    raise
	    except Exception as e:
		logging.exception('socket error: %s', e)
		raise

            # Bad request, stop doing crlf injection
	    if response.app_status in (400, 405):
		http.crlf = 0

            # Send the result back to user browser
	    wfile = sock.makefile('wb', 0)

            # Format Set-Cookie field, TODO: why doing this?
	    if 'Set-Cookie' in response.msg:
		response.msg['Set-Cookie'] = re.sub(', ([^ =]+(?:=|$))', '\\r\\nSet-Cookie: \\1', response.msg['Set-Cookie'])

            # Write the response head to socket. Do not set transfer-encoding, TODO: why doing this?
	    wfile.write('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'transfer-encoding')))

	    # Write the response payload to socket
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

    ##
    # @brief    Wrap the user browser's request into a POST request's payload, send the POST request to proxy_server
    #           Get the proxy_server's response, unwarp the content.
    #           
    #           request payload structure: metadata_length(2 bytes), metadata, payload
    #
    # @param    method:     request method(GET POST ...)
    # @param    url:        requesting url
    # @param    headers:    request headers
    # @param    payload:    payload of the request
    # @param    fetchserver:proxy server url
    # @param    kwargs:     other params, there params will be send to proxy server in header
    #
    # @return   response object
    def paas_urlfetch(self, method, url, headers, payload, fetchserver, **kwargs):
	http = self.http_handler

        # Compress the payload if the payload is not encoding or compressed.
	if payload:
	    if len(payload) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
		zpayload = zlib.compress(payload)[2:-4]
		if len(zpayload) < len(payload):
		    payload = zpayload
		    headers['Content-Encoding'] = 'deflate'
	    headers['Content-Length'] = str(len(payload))

        # TODO: why skip some headers?
	skip_headers = http.skip_headers

        # Wrap user request into payload
	metadata = 'User-Method:%s\nUser-Url:%s\n%s\n%s\n' % (method, url, '\n'.join('User-%s:%s'%(k,v) for k,v in kwargs.iteritems() if v), '\n'.join('%s:%s'%(k,v) for k,v in headers.iteritems() if k not in skip_headers))
	metadata = zlib.compress(metadata)[2:-4]

        # Send packed metadata lenth, metadata and payload
	app_payload = '%s%s%s' % (struct.pack('!h', len(metadata)), metadata, payload)

        # Send the composed request to proxy server by a POST request. DO NOT DO CRLF INJECTION AT PRESENT.
	response = http.request('POST', fetchserver, app_payload, {'Content-Length':len(app_payload)}, crlf=0)

        # The status of the proxy server's response is stored in app_status.
        # The status of the user's real request is stored in status.
        # TODO: what is x-status?
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




