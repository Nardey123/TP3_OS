default : servtcp_mt clitcp

CFLAGS = -Wall -D_REENTRANT

clitcp : clitcp.c
	cc -Wall -o clitcp clitcp.c

servtcp_mt : servtcp_mt.c
	cc $(CFLAGS) -o servtcp_mt servtcp_mt.c -pthread

clean :
	rm -f servtcp_mt clitcp

