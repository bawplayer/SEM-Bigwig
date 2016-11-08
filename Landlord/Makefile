CC=gcc

init: clean
	pip install -r requirements.txt
	python setup.py build
test:
	nasm -f elf tst/tiny.asm
	$(CC) -m32 -s tst/tiny.o -o tst/tiny.out -nostdlib
	rm tst/tiny.o
clean:
	rm -rf build
	rm -f ./*.so
