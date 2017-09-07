#==========================================================================
#        Author:  Yu Yang
#         Email:  yyangplus@NOSPAM.gmail.com
#       Created:  2017-09-02 Sat 11:19
#==========================================================================
FF_DPDK_TARGET ?= x86_64-native-linuxapp-gcc
all: dpdk fstack

dpdk: cfstack
	cd cfstack/dpdk && make install T=$(FF_DPDK_TARGET) CONFIG_RTE_BUILD_COMBINE_LIBS=y EXTRA_CFLAGS="-fPIC" -j 4

.PHONY: dpdk

fstack: cfstack
	cd cfstack/lib && make CONF_CFLAGS="-fPIC"

.PHONY: fstack

cfstack:
	git submodule update --init

clean:
	cd cfstack/lib && make clean; \
	cd cfstack/dpdk && rm -rf $(FF_DPDK_TARGET)

.PHONY: clean
