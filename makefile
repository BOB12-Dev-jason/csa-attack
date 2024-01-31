LDLIBS += -lpcap

all: csa-attack

csa-attack: *.c

clean:
	rm -f csa-attack *.o
