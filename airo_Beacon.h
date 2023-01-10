#pragma once
#include <cstring>
#include <iostream>

typedef struct BeaconFrame {
    u_int8_t Type_Beacon;
    char Receiver_address[12]; 
    char Transmitter_address[12];
    char BSSID[12];
}BeaconFrame;