cmake_minimum_required(VERSION 3.10.2)

set(libs_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../libs)

add_library(
        tari_crypto
        STATIC
        IMPORTED
)
set_target_properties(
        tari_crypto
        PROPERTIES
        IMPORTED_LOCATION ${libs_DIR}/${ANDROID_ABI}/libtari_crypto.a
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_library(
        native-lib SHARED
        jniCommon.cpp
        jniTariCrypto.cpp
)

find_library(
        log-lib
        log
)

target_include_directories(
        native-lib PRIVATE ${libs_DIR}/
)

target_link_libraries(
                       native-lib
                       android
                       tari_crypto
                       ${log-lib}
                       "-Wl,--allow-multiple-definition"
)
