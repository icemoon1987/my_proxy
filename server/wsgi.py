#!/usr/bin/python
import os

virtenv = os.environ['OPENSHIFT_PYTHON_DIR'] + '/virtenv/'
virtualenv = os.path.join(virtenv, 'bin/activate_this.py')
try:
    execfile(virtualenv, dict(__file__=virtualenv))
except IOError:
    pass
#
# IMPORTANT: Put any additional includes below this line.  If placed above this
# line, it's possible required libraries won't be in your searchable path
#

import sys
import os
import re
import time
import struct
import zlib
import binascii
import logging
import httplib
import urlparse
import base64
import cStringIO
import hashlib
import hmac
import errno

try:
    import socket, select, ssl, thread
except:
    socket = None

def application(environ, start_response):

    if environ['PATH_INFO'] == '/health':
        # health check by openshift
        ctype = 'text/plain'
        response_body = "1"

    elif environ['PATH_INFO'] == '/env':
        # environment params by openshift
        ctype = 'text/plain'
        response_body = ['%s: %s' % (key, value) for key, value in sorted(environ.items())]
        response_body = '\n'.join(response_body)

    elif environ['REQUEST_METHOD'] == 'GET':
        # GET request will get a fake page 
        ctype = 'text/html'
        response_body = "<html><body><p>Hello World!</p></body></html>"

    elif environ['REQUEST_METHOD'] == 'POST':
        # process requests from proxy client
        ctype = 'text/html'
        try:
            # parse proxy client requests
            wsgi_input = environ["wsgi.input"]
            data = wsgi_input.read(2)

            # decompress user request
            metadata_length, = struct.unpack('!h', data)
            metadata = wsgi_input.read(metadata_length)
            metadata = zlib.decompress(metadata, -15)
            headers  = dict(x.split(':', 1) for x in metadata.splitlines() if x)
            method   = headers.pop('User-Method')
            url   = headers.pop('User-Url')

            kwargs   = {}
            any(kwargs.__setitem__(x[2:].lower(), headers.pop(x)) for x in headers.keys() if x.startswith('User-'))

            headers['Connection'] = 'close'

            payload = environ['wsgi.input'].read() if 'Content-Length' in headers else None

            if 'Content-Encoding' in headers:
                if headers['Content-Encoding'] == 'deflate':
                    payload = zlib.decompress(payload, -15)
                    headers['Content-Length'] = str(len(payload))
                    del headers['Content-Encoding']

            timeout = 60

            logging.info('%s "user-method:%s user-url:%s %s" - -', environ['REMOTE_ADDR'], method, url, 'HTTP/1.1')

            # TODO: process CONNECT request 
            if method != 'CONNECT':

                # get user request url
                scheme, netloc, path, params, query, fragment = urlparse.urlparse(url)
                HTTPConnection = httplib.HTTPSConnection if scheme == 'https' else httplib.HTTPConnection
                if params:
                    path += ';' + params
                if query:
                    path += '?' + query

                # access the url and get the result
                conn = HTTPConnection(netloc, timeout=timeout)
                conn.request(method, path, body=payload, headers=headers)
                response = conn.getresponse()

                # send the result back to proxy client
                headers = [('X-Status', str(response.status))]
                headers += [(k, v) for k, v in response.msg.items() if k != 'transfer-encoding']

                data = ""

                # Read 8k data each time
                while True:
                    tmp = response.read(8192)
                    if not tmp:
                        response.close()
                        break
                    else:
                        data += tmp
                
                #data = response.read()

                start_response('200 OK', headers)
                response_body = data

                return [response_body]

        except Exception, ex:
            ctype = 'text/html'
            response_body = "<html><body><p>" + ex.__str__() + "</p></body></html>"

    status = '200 OK'
    response_headers = [('Content-Type', ctype), ('Content-Length', str(len(response_body)))]
    start_response(status, response_headers)

    return [response_body]


#
# Below for testing only
#
if __name__ == '__main__':
    from wsgiref.simple_server import make_server

    msg = "test"

    httpd = make_server('localhost', 8051, application)
    # Wait for a single request, serve it and quit.
    httpd.handle_request()



