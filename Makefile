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
clean:
	rm nipperpatch.go
test: all
# Dump ROM3 from the card.
	sudo nippertool -dumprom rom3.bin
# Take its MD5 hash.
	md5sum -c md5.txt




