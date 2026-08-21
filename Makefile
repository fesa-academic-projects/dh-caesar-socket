.PHONY: build test slides diff clean

build:
	python3 build.py

test: build
	python3 python/test_all.py

slides: build
	python3 python/slides.py

diff:
	@echo '=== Simple_tcpServer.py ==='
	@diff -u --strip-trailing-cr original/Simple_tcpServer.py python/Simple_tcpServer.py || true
	@echo
	@echo '=== Simple_tcpClient.py ==='
	@diff -u --strip-trailing-cr original/Simple_tcpClient.py python/Simple_tcpClient.py || true

clean:
	rm -rf python/_crypto.c python/*.o python/*.so python/__pycache__ python/home
