all: ana catch

ana: data_analysis.o
	gcc $< -o $@ -lpcap

catch: catch_packet.o
	gcc $< -o $@ -lpcap -lpthread

catch_packet.o: catch_packet.c
	gcc -c catch_packet.c -o catch_packet.o -g

data_analysis.o: data_analysis.c
	gcc -c data_analysis.c -o data_analysis.o -g

clean:
	rm -rf ana catch *.o *.data