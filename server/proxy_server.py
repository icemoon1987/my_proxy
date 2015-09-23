#!/usr/bin/env python
# coding:utf-8

__version__ = '1.0.0'
__bufsize__ = 1024*1024

class proxy_server(object):

	def __init__(self, listen_ip, listen_port):

		self.listen_ip = listen_ip
		self.listen_port = listen_port

		if cfg.DEBUG_SWITCH:
			log_level = logging.DEBUG
		else:
			log_level = logging.INFO

		logging.basicConfig(format="%(levelname)s:\t%(asctime)s\t%(name)s\t%(message)s", level = log_level)
		self.logger = logging.getLogger("proxy_server")

		return

	def proxy_handler(self, sock, address):

		#try:
		# Receive and parse user requests
		rfile = sock.makefile('rb', __bufsize__)

		#user_request = self.http_handler.parse_request(rfile)

		# Compose proxy requests
		#proxy_request = self.compose_proxy_request(user_request)

		# Send proxy request to server, and get proxy response
		#proxy_response = self.send_proxy_request(proxy_request, cfg.PROXY_SERVER)

		# Get proxy respons from server

		# Parse proxy respons

		# Send respons back to user
		#user_addr, user_port = address

		#except Exception, ex:
			#self.logger.warning(ex.__str__())
			#return

		return


	def run(self):

		self.logger.info("proxy_server init finish.")
		server = gevent.server.StreamServer((self.listen_ip, self.listen_port), self.proxy_handler)
		self.logger.info("proxy_server listen on: %s:%d" % (self.listen_ip, self.listen_port) )

		server.serve_forever()

		return


if __name__ == '__main__':
	try:
		server = proxy_server(cfg.LISTEN_IP, cfg.LISTEN_PORT)
		server.run()
	except KeyboardInterrupt:
		pass
	except Exception, ex:
		print ex.__str__()
