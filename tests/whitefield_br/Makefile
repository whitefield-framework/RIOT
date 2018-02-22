APPLICATION = riot-whitefield-br

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP -Wall

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 0

USEPKG += whitefield

USEMODULE += whitefield
USEMODULE += xtimer
USEMODULE += random
#USEMODULE += shell
#USEMODULE += shell_commands
USEMODULE += ps
USEMODULE += ipv6_addr
USEMODULE += gnrc_udp
USEMODULE += gnrc_rpl
USEMODULE += gnrc_icmpv6
USEMODULE += auto_init_gnrc_rpl
#USEMODULE += gnrc_icmpv6_echo
#USEMODULE += gnrc_ipv6_router_default
USEMODULE += auto_init_gnrc_netif
#USEMODULE += gnrc_sixlowpan
USEMODULE += gnrc_sixlowpan_iphc
USEMODULE += gnrc_sixlowpan_frag
USEMODULE += gnrc_netdev
USEMODULE += gnrc_ipv6_netif
USEMODULE += netstats_l2
USEMODULE += netstats_ipv6
USEMODULE += netstats_rpl
USEMODULE += gnrc_sixlowpan_border_router_default
USEMODULE += gnrc_icmpv6_echo
USEMODULE += fib
USEMODULE += gnrc_uhcpc

TAP ?= tap0
IPV6_PREFIX ?= 2001:db8::/64

#required for C++ compiling
#CXXEXFLAGS += -fno-rtti
#USEMODULE += cpp11-compat

export LINKFLAGS += -L$(RIOTBASE)/../../bin -lwf_commline_32
CFLAGS += -DGNRC_PKTBUF_SIZE=90

include $(RIOTBASE)/Makefile.include

