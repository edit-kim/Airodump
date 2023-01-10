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
	printf("syntax: airodump <interface>\n");
	printf("sample: airodump wlan0\n");
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
	// 1000 
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

		u_char beaconCheck = { 0x80 };

		// packet check
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		memcpy(&airodump.RadiotapHeader.it_version, &packet[0], 1);
		memcpy(&airodump.RadiotapHeader.it_len, &packet[2], 1);
		memcpy(&airodump.RadiotapHeader.it_signal, &packet[18], 1);

		int header_len = airodump.RadiotapHeader.it_len;

		memcpy(&airodump.BeaconFrame.Type_Beacon, &packet[header_len], 1);
		memcpy(&airodump.BeaconFrame.Receiver_address, &packet[header_len + 4], 6);

		memcpy(&airodump.BeaconFrame.Transmitter_address, &packet[header_len + 10], 6);
		memcpy(&airodump.BeaconFrame.BSSID, &packet[header_len + 16], 6);

		int wireless_start = header_len + 24;
		int fixed_para = 12;

		memcpy(&airodump.WirelessManagement.Fixed_Parameters, &packet[wireless_start], 12);

		int first_tag_len = packet[wireless_start+fixed_para+1]; /* 61 */
		memcpy(&airodump.WirelessManagement.SSID, &packet[wireless_start+fixed_para+2], first_tag_len); /* 68 */

		int second_tag_len = packet[wireless_start+fixed_para+2+first_tag_len+1]; /* 61 + 7 + 2*/ /* 70 */
		memcpy(&airodump.WirelessManagement.Supported_Rates, &packet[wireless_start+fixed_para+2+first_tag_len+2], second_tag_len); /*71 부터 +8*/

		int third_tag_len = packet[wireless_start+fixed_para+2+first_tag_len+2+second_tag_len+1]; /* 70 -1 + 1 + 8*/ /* 80 */
		memcpy(&airodump.WirelessManagement.Current_Channel, &packet[wireless_start+fixed_para+2+first_tag_len+2+second_tag_len+2], third_tag_len);

		
		printf("start!");
		printf("\n");
		printf("BSSID\t\t\tBeacons\t\t\tCH\t\t\tSSID");

		// copy packet data to Airodump
		// beaconFrame check
		if(memcmp(&airodump.BeaconFrame.Type_Beacon, &beaconCheck, 1) == 0){

			printf("%02x", airodump.RadiotapHeader.it_signal);
			
			printf("%02x:%02x:%02x:%02x:%02x:%02x \t", airodump.BeaconFrame.BSSID);
			printf("%02x:%02x:%02x:%02x:%02x:%02x \t", airodump.BeaconFrame.Receiver_address);
			printf("%02x:%02x:%02x:%02x:%02x:%02x \t", airodump.BeaconFrame.Transmitter_address);
			

			printf("%d \t", airodump.WirelessManagement.Current_Channel);
			printf("%s \t", airodump.WirelessManagement.SSID);

		}
		else
		 	continue;

	}

	pcap_close(pcap);
}
