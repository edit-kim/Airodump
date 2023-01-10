#pragma once
#include <cstring>
#include <iostream>

typedef struct BeaconFrame {
    u_int8_t type_Beacon;
    char Receiver_address[18]; 
    char Transmitter_address[18];
    char BSSID[18];
}BeaconFrame;