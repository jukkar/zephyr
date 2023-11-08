# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(crime)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/http_server)
include(${ZEPHYR_BASE}/subsys/net/lib/http/server/crime.cmake)

FILE(GLOB app_sources src/main.c)

target_sources(app PRIVATE ${app_sources})
http_server_generate_crime_res(service_A app ${CMAKE_CURRENT_LIST_DIR}/service_A)
http_server_generate_crime_res(service_B app ${CMAKE_CURRENT_LIST_DIR}/service_B)
