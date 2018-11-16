all:
	gcc *.c -o proxy -lpcap

clean:
	-rm -rf *.o proxy
