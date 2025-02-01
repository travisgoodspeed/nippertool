# Howdy y'all,
#
# This Makefile is intended for assembling the shellcode into Golang
# code, and out of laziness, it also call go build.  I hope you find
# it convenient if you'd like to experiment with modifications to the
# shellcode on Dish Network ROM3 cards.
#
# --Travis


all: nippertool

nippertool: nipperpatch.go
	go build

nipperpatch.go: nipperpatch.asm
	goodasm nipperpatch.asm -LGa > nipperpatch.go
listing: nipperpatch.asm
	goodasm nipperpatch.asm -Lab
clean:
	rm -f nipperpatch.go

quicktest: all
	sudo ./nippertool -peek 0x4000 | grep "06 01 1b cc 20 00 20 fe 06 01 1e cc 20 09 20 fe "

test: all
# Dump ROM3 from the card.
	sudo nippertool -dumprom rom3.bin -progress
# Take its MD5 hash.
	md5sum -c md5.txt

try: all
	sudo ./nippertool -peek 0x4000 -verbose


