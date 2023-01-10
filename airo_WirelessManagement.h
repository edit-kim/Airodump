#pragma once

#include <iostream>
#include <cstring>
#include <string>

typedef struct WirelessManagement {
    char Fixed_Parameters[12];
    char* SSID;
    char* Supported_Rates;
    int Current_Channel;
}WirelessManagement;