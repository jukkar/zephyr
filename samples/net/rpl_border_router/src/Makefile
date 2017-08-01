#
# Copyright (c) 2017 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

# List of files that are used to generate .h file that can be included
# into .c file.
generate_inc_file += \
	echo-apps-cert.der \
	echo-apps-key.der

generate_inc_gz_file += \
	index.html \
	favicon.ico \
	br.js \
	style.css

include $(ZEPHYR_BASE)/scripts/Makefile.gen

include $(ZEPHYR_BASE)/samples/net/common/Makefile.common

ccflags-y += -I$(ZEPHYR_BASE)/subsys/net/ip

obj-y += main.o
obj-y += rpl.o

obj-$(CONFIG_HTTP_SERVER) += http.o
obj-$(CONFIG_NET_SHELL) += shell.o
