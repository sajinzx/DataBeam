#include <iostream>
#include <pthread.h>
#include <ctime>
#include <windows.h>
int main() {
    timespec now;
    int res = clock_gettime(CLOCK_MONOTONIC, &now);
    std::cout << "res=" << res << " sec=" << now.tv_sec << " nsec=" << now.tv_nsec << std::endl;
    Sleep(100);
    int res2 = clock_gettime(CLOCK_MONOTONIC, &now);
    std::cout << "res2=" << res2 << " sec=" << now.tv_sec << " nsec=" << now.tv_nsec << std::endl;
    return 0;
}
