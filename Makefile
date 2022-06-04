.PHONY: build
build:
	cmake -B build && cmake --build build --parallel

.PHONY: ninja
ninja:
	cmake -B build -G Ninja && cmake --build build --parallel

.PHONY: dist
dist: build
	cmake --install build --prefix dist

.PHONY: clean
clean:
	@rm -Rf build dist CMakeCache.txt CMakeFiles
