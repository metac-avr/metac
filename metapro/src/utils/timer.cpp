#include "utils/timer.h"

#include <time.h>

Timer::Timer(): start(time(NULL)) { }

time_t Timer::stopTimer() {
    return time(NULL) - start;
}