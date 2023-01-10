#pragma once

#include <iostream>
#include <cstring>
#include <string>

typedef struct WirelessManagement {
    char Fixed_Parameters[12];
    char SSID[25];
    char* Supported_Rates;
    int8_t Current_Channel;
}WirelessManagement;