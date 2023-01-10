#pragma once

#include <iostream>
#include <cstring>
#include <string>

struct WirelessManagement {
    char Fixed_Parameters[12];
    char* SSID;
    char* Supported_Rates;
    int Current_Channel;
};