FIND_LIBRARY(PCAP pcap REQUIRED)

SET(CXX_SOURCES
        roll.cpp
        utils.cpp
        )

add_executable(Main
        main.cpp
        http_trace.cpp
        dns_trace.cpp
        ${CXX_SOURCES}
        )

add_executable(ReceiveRatio
        receiveRatio.cpp
        tcp_receive.cpp
        ${CXX_SOURCES}
        )

add_executable(WifiError
        wifi_error.cpp)

add_executable(WifiErrorSyn
        wifi_error_syn.cpp)

TARGET_LINK_LIBRARIES(Main ${PCAP})
TARGET_LINK_LIBRARIES(ReceiveRatio ${PCAP})
TARGET_LINK_LIBRARIES(WifiError ${PCAP})
TARGET_LINK_LIBRARIES(WifiErrorSyn ${PCAP})
