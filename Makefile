.PHONY: build test slides clean

build:
	python3 build.py

test: build
	python3 python/test_all.py

slides: build
	python3 python/slides.py

clean:
	rm -rf python/_crypto.c python/*.o python/*.so python/__pycache__ python/home
