FIND_LIBRARY(PCAP pcap REQUIRED)

add_executable(Main
        main.cpp
        http_trace.cpp
        dns_trace.cpp
        utils.cpp
        roll.cpp
        )

TARGET_LINK_LIBRARIES(Main ${PCAP})
