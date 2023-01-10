#include <pcap.h>
#include <iostream>
#include <cstring>
#include <vector>
#include <ctime>
#include "airo_Beacon.h"
#include "airo_Radiotap.h"
#include "airo_WirelessManagement.h"
#include "airodump.h"

using namespace std;

void usage() {
	printf("syntax: Airodump <interface>\n");
	printf("sample: Airodump wlan0\n");
}

void Print_Airodump(int channel) {

}


int main(int argc, char* argv[]) {

	if(argc < 2) {
		usage();
		return -1;
	}

	char* interface = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

	// can't capture the pcap bcz of interface
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
		return -1;
	}
	while (true) {
		// get the packet
		struct pcap_pkthdr* header;
		const u_char* packet;

		AirodumpData airodump;
		// char tempt[13] = "asdfasdfasdf";
		// memcpy(&airodump.beaconFrame.Receiver_address, &tempt, 13);
		// printf("%s", airodump.beaconFrame.Receiver_address);

		u_int8_t beaconCheck = 128;

		// packet check
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		printf("check \t");
		memcpy(&airodump.radiotapHeader.it_version, &packet[0], 1);
		memcpy(&airodump.radiotapHeader.it_len, &packet[2], 2);
		memcpy(&airodump.radiotapHeader.it_signal, &packet[18], 1);
		
		u_int16_t header_len = airodump.radiotapHeader.it_len;
		printf("header_len : %d bytes \t", header_len);
		printf("it_signal : %d \t", airodump.radiotapHeader.it_signal);

		memcpy(&airodump.beaconFrame.type_Beacon, &packet[header_len], 1);
		memcpy(&airodump.beaconFrame.Receiver_address, &packet[header_len + 4], 6);
		printf("beacon type : %u \n", airodump.beaconFrame.type_Beacon);

		u_char temp[6];
		memcpy(&temp, &packet[header_len+4], 6);
		std::cout << "0" << std::endl;
		sprintf(airodump.beaconFrame.Receiver_address, "%02x:%02x:%02x:%02x:%02x:%02x", temp[0]
		, temp[1], temp[2], temp[3], temp[4], temp[5]);
		std::cout << "1" << std::endl;
		printf("receiver_address : %s \t", airodump.beaconFrame.Receiver_address);

		// memcpy(&airodump.beaconFrame.Transmitter_address, &packet[header_len + 10], 6);
		memcpy(&temp, &packet[header_len+10], 6);
		sprintf(airodump.beaconFrame.Transmitter_address, "%02x:%02x:%02x:%02x:%02x:%02x", temp[0]
		, temp[1], temp[2], temp[3], temp[4], temp[5]);
		printf("transmitter_address : %s \t", airodump.beaconFrame.Transmitter_address);


		// memcpy(&airodump.beaconFrame.BSSID, &packet[header_len + 16], 6);
		memcpy(&temp, &packet[header_len+16], 6);
		sprintf(airodump.beaconFrame.BSSID, "%02x:%02x:%02x:%02x:%02x:%02x", temp[0]
		, temp[1], temp[2], temp[3], temp[4], temp[5]);
		printf("BSSID : %s \t", airodump.beaconFrame.BSSID);

		// 잘 됨 여기까진 ^^
		// return 0;

		int wireless_start = header_len + 24;
		int fixed_para = 12;

		memcpy(&airodump.wirelessManagement.Fixed_Parameters, &packet[wireless_start], 12);

		int first_tag_len = packet[wireless_start+fixed_para+1]; /* 61 */
		memcpy(&airodump.wirelessManagement.SSID, &packet[wireless_start+fixed_para+2], first_tag_len); /* 68 */
		printf("SSID : %s \t", airodump.wirelessManagement.SSID);

		int second_tag_len = packet[wireless_start+fixed_para+2+first_tag_len+1]; /* 61 + 7 + 2*/ /* 70 */
		memcpy(&airodump.wirelessManagement.Supported_Rates, &packet[wireless_start+fixed_para+2+first_tag_len+2], second_tag_len); /*71 부터 +8*/

		int third_tag_len = packet[wireless_start+fixed_para+2+first_tag_len+2+second_tag_len+1]; /* 70 -1 + 1 + 8*/ /* 80 */
		memcpy(&airodump.wirelessManagement.Current_Channel, &packet[wireless_start+fixed_para+2+first_tag_len+2+second_tag_len+2], third_tag_len);

		printf("\n");

		// printf("BSSID\t\t\tBeacons\t\t\tCH\t\t\tSSID");
		// printf("%02x", airodump.beaconFrame.Type_Beacon);

		// copy packet data to Airodump
		// beaconFrame check
		if(memcmp(&airodump.beaconFrame.type_Beacon, &beaconCheck, 1) == 0){

			printf("%x", airodump.radiotapHeader.it_signal);
			
			printf("%s \t", airodump.beaconFrame.BSSID);
			printf("%s \t", airodump.beaconFrame.Receiver_address);
			printf("%s \t", airodump.beaconFrame.Transmitter_address);
			

			printf("%d \t", airodump.wirelessManagement.Current_Channel);
			printf("%s \t", airodump.wirelessManagement.SSID);

		}
		else
		 	continue;

	}

	pcap_close(pcap);
}
