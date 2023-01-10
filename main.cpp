#include <pcap.h>
#include <iostream>
#include <cstring>
#include <vector>
#include <ctime>
#include <unistd.h>
#include "airo_Beacon.h"
#include "airo_Radiotap.h"
#include "airo_WirelessManagement.h"
#include "airodump.h"

using namespace std;

void usage() {
	printf("syntax: Airodump <interface>\n");
	printf("sample: Airodump wlan0\n");
}

void printAirodump_ng(int CH, std::vector<AirodumpData> airodumplist)
{
    std::time_t t =std::time(nullptr);
    std::tm* now = std::localtime(&t);

    printf("CH %d\t][ Elapsed: %d s ][ %d-%02d-%02d %d:%d\n", CH, 0, now->tm_year + 1900, now->tm_mon+1, now->tm_mday, now->tm_hour, now->tm_min);
    printf("\n");
    printf("BSSID\t\t\tSignal\tBecons\tChannel\t\tSSID\n");

    for(int i = 0; i < airodumplist.size(); i++)
    {
        printf("%s\t%d\t%d\t%d\t\t%s\n", airodumplist[i].beaconFrame.BSSID, airodumplist[i].radiotapHeader.it_signal, airodumplist[i].beacon, 
		airodumplist[i].wirelessManagement.Current_Channel, airodumplist[i].wirelessManagement.SSID);
    }
	sleep(1);
	system("clear");
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

	std::vector<AirodumpData> airolist;

	while (true) {
		// get the packet
		struct pcap_pkthdr* header;
		const u_char* packet;

		AirodumpData airodump;

		u_int8_t beaconCheck = 128;

		// packet check
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		memcpy(&airodump.radiotapHeader.it_version, &packet[0], 1);
		memcpy(&airodump.radiotapHeader.it_len, &packet[2], 2);
		memcpy(&airodump.radiotapHeader.it_signal, &packet[18], 1);
		
		u_int16_t header_len = airodump.radiotapHeader.it_len;

		memcpy(&airodump.beaconFrame.type_Beacon, &packet[header_len], 1);
		memcpy(&airodump.beaconFrame.Receiver_address, &packet[header_len + 4], 6);

		// beacon check
		if(airodump.beaconFrame.type_Beacon != 128)
			continue;

		u_char temp[6];
		memcpy(&temp, &packet[header_len+4], 6);
		sprintf(airodump.beaconFrame.Receiver_address, "%02x:%02x:%02x:%02x:%02x:%02x", temp[0]
		, temp[1], temp[2], temp[3], temp[4], temp[5]);

		memcpy(&temp, &packet[header_len+10], 6);
		sprintf(airodump.beaconFrame.Transmitter_address, "%02x:%02x:%02x:%02x:%02x:%02x", temp[0]
		, temp[1], temp[2], temp[3], temp[4], temp[5]);

		memcpy(&temp, &packet[header_len+16], 6);
		sprintf(airodump.beaconFrame.BSSID, "%02x:%02x:%02x:%02x:%02x:%02x", temp[0], temp[1], temp[2], temp[3], temp[4], temp[5]);

		int wireless_start = header_len + 24;
		int fixed_para = 12;

		memcpy(&airodump.wirelessManagement.Fixed_Parameters, &packet[wireless_start], 12);

		int first_tag_len = (int)packet[wireless_start+fixed_para+1];
		
		if (first_tag_len == 0) {
			char missing_SSID[2] = "-";
			memcpy(&airodump.wirelessManagement.SSID, &missing_SSID, 2);
		}
		else {
			memcpy(&airodump.wirelessManagement.SSID, &packet[wireless_start+fixed_para+2], first_tag_len); 
		}
		airodump.wirelessManagement.SSID[first_tag_len] = '\0';

		int second_tag_len = (int)packet[wireless_start+fixed_para+2+first_tag_len+1]; 
		airodump.wirelessManagement.Supported_Rates = (char*)malloc(second_tag_len);
		memcpy(&airodump.wirelessManagement.Supported_Rates, &packet[wireless_start+fixed_para+2+first_tag_len+2], second_tag_len); /*71 부터 +8*/

		int third_tag_len = (int)packet[wireless_start+fixed_para+2+first_tag_len+2+second_tag_len+1];
		memcpy(&airodump.wirelessManagement.Current_Channel, &packet[wireless_start+fixed_para+2+first_tag_len+2+second_tag_len+2], third_tag_len);
		bool checker = false;
        for(int i= 0; i < airolist.size(); i++)
        {
            if(strcmp(airolist[i].beaconFrame.BSSID, airodump.beaconFrame.BSSID) == 0)
            {   
                checker = true;
                airolist[i].radiotapHeader.it_signal = airodump.radiotapHeader.it_signal;
				airolist[i].beacon +=1;
				break;
            }
        }
		if(checker == false)
			airolist.push_back(airodump);
	
		printAirodump_ng(airodump.wirelessManagement.Current_Channel, airolist);
	}

	pcap_close(pcap);
}
