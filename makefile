#Makefile
all:	netfilter-test
netfilter-test: 
		gcc -o netfilter-test netfilter-test.c -lnetfilter_queue
clean:
		rm netfilter-test
