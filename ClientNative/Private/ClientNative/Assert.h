#pragma once

#include <iostream>

#define LIVE_ASSERT(condition, message)                                              \
    do {                                                                        \
        if (!(condition)) {                                                     \
            std::cout << "ASSERTION FAILED: " << #condition        \
                      << "\nFile: " << __FILE__                                 \
                      << "\nLine: " << __LINE__                                 \
                      << "\nMessage: " << message << std::endl;  \
            std::abort();                                                       \
        }                                                                       \
    } while (0)