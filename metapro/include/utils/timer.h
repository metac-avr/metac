#pragma once

#include <time.h>

class Timer {
private:
    time_t start;
public:
    Timer();
    time_t stopTimer();
};