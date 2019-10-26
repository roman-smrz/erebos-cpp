all: build/Makefile
	+make -C build
.PHONY: all

build/Makefile:
	mkdir -p build
	(cd build; cmake ..)

clean:
	rm -rf build
.PHONY: clean
