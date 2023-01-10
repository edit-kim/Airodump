LDLIBS += -lpcap

all: Airodump

airo_Radiotap.o: airo_Radiotap.h airo_Radiotap.cpp

airo_Beacon.o: airo_Beacon.h airo_Beacon.cpp

airo_WirelessManagement.o: airo_WirelessManagement.o airo_WirelessManagement.cpp

airodump.o: airodump.h airodump.cpp

main.o: main.cpp

Airodump: airo_Radiotap.o airo_Beacon.o airo_WirelessManagement.o airodump.o main.o

clean:
	rm -f Airodump *.o
	rm -f ../build/Airodump
