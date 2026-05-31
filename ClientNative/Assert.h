#pragma once

#include <iostream>

/*
 * ASSERT 매크로입니다.
 * Debug 빌드에서도 std::abort()를 호출하여 프로그램을 종료시키도록 구현되어 있습니다.
 */
#define LIVE_ASSERT(condition, message)                                         \
    do {                                                                        \
        if (!(condition)) {                                                     \
            std::cout << "ASSERTION FAILED: " << #condition                     \
                      << "\nFile: " << __FILE__                                 \
                      << "\nLine: " << __LINE__                                 \
                      << "\nMessage: " << message << std::endl;                 \
            std::abort();                                                       \
        }                                                                       \
    } while (0)