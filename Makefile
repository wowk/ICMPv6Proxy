all:
	gcc *.c -o proxy

clean:
	-rm -rf *.o proxy
