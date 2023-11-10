# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(crime)

set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/http_server)
include(${ZEPHYR_BASE}/subsys/net/lib/http/server/crime.cmake)

set(app_sources)

# tests are in main.c
list(APPEND app_sources src/main.c)

# Note: all resources defined in the .c files below have static linkage and are therefore *not*
# visible to the testsuite via C identifier.

# Automatically generate a .c file for service_A resources
#
# This is intended to be the primary means by which users define compresses resources at build
# time as it scales well and requires the least amount of work by users.
zephyr_iterable_section(NAME http_resource_desc_service_A KVMA RAM_REGION GROUP RODATA_REGION SUBALIGN 4)
http_server_generate_crime_res(service_A app ${CMAKE_CURRENT_LIST_DIR}/src/service_A)

# Manually create a .c file for service_B resources
#
# This approach could be used for small designs with one or two compressed resources. Manually
# creating compressed resources involves significantly more work than using the automatic method
# above.
# 
# - index.html
#   - compressed manually with gzip
#   - converted manually to C array with xxd
# - js/service-B.js
#   - compressed and converted to C array with generate_inc_file_for_target()
list(APPEND app_sources src/service_B.c)
generate_inc_file_for_target(app ${CMAKE_CURRENT_LIST_DIR}/src/service_B/js/service-B.js ${gen_dir}/service_B/js/service-B.js.inc)
zephyr_linker_sources(SECTIONS src/service-B-rom-sections.ld)
zephyr_iterable_section(NAME http_resource_desc_service_B KVMA RAM_REGION GROUP RODATA_REGION SUBALIGN 4)

target_sources(app PRIVATE ${app_sources})
