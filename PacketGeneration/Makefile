all: generator ipPacketGenerator voipInvitePacketGenerator
generator: generator.o udpPacketGenerator.o
	gcc -o ../bin/generator generator.o udpPacketGenerator.o

generator.o: udpPacketGenerator.h generator.c
	gcc -c generator.c

udpPacketGenerator.o: udpPacketGenerator.h udpPacketGenerator.c
	gcc -c udpPacketGenerator.c

ipPacketGenerator: 
	gcc -o ../bin/ipPacketGenerator ipPacketGenerator.c

voipInvitePacketGenerator: udpPacketGenerator.o voipInvitePacketGenerator.o
	gcc -o ../bin/voipInvitePacketGenerator voipInvitePacketGenerator.o udpPacketGenerator.o

voipInvitePacketGenerator.o: udpPacketGenerator.h voipInvitePacketGenerator.c
	gcc -c voipInvitePacketGenerator.c

clean:
	rm -rf *.o
	rm -rf ../bin/generator
	rm -rf ../bin/ipPacketGenerator
	rm -rf ../bin/voipInvitePacketGenerator
