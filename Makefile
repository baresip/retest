.PHONY: build
build:
	cmake -B build && cmake --build build --parallel
	mv build/retest retest

.PHONY: ninja
ninja:
	cmake -B build -G Ninja && cmake --build build --parallel

.PHONY: dist
dist: build
	cmake --install build --prefix dist

.PHONY: clean
clean:
	@rm -Rf build dist CMakeCache.txt CMakeFiles

.PHONY: test
test: build
	./retest -r -d data
