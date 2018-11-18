all:
	gcc *.c -o proxy -g
	cp proxy /tmp

clean:
	-rm -rf *.o proxy
