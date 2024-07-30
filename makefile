LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap.c
	$(CC) -o pcap-test pcap.c $(LDLIBS)

clean:
	rm -f pcap-test *.o

