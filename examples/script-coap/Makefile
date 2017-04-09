# name of your application
APPLICATION = script-coap

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../..

BOARD_INSUFFICIENT_MEMORY := airfy-beacon calliope-mini cc2650stk maple-mini \
                             microbit nrf51dongle nrf6310 nucleo-f030 nucleo-f070 \
                             nucleo-f072 nucleo-f103 nucleo-f302 nucleo-f334 nucleo-f410 \
                             nucleo-l053 nucleo-l073 nucleo32-f031 nucleo32-f042 \
                             nucleo32-f303 nucleo32-l031 opencm904 pca10000 \
                             pca10005 spark-core stm32f0discovery weio yunjia-nrf51822 \

BOARD_BLACKLIST := arduino-duemilanove arduino-mega2560 arduino-uno chronos \
                   msb-430 msb-430h qemu-i386 telosb waspmote-pro wsn430-v1_3b \
                   wsn430-v1_4 z1

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += gnrc_netdev_default
USEMODULE += auto_init_gnrc_netif
# Specify the mandatory networking modules for IPv6 and UDP
USEMODULE += gnrc_udp
# Additional networking modules that can be dropped if not needed
USEMODULE += gnrc_icmpv6_echo

#
USEMODULE += gnrc_sock_udp

USEPKG += nanocoap
# optionally enable nanocoap's debug output
#CFLAGS += -DNANOCOAP_DEBUG

# include this for nicely formatting the returned internal value
USEMODULE += fmt

# include this for printing IP addresses
USEMODULE += shell_commands

# Add the package for Jerryscript
USEPKG += jerryscript

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
#CFLAGS += -DDEVELHELP

# Set stack size to something (conservatively) enormous
CFLAGS += -DTHREAD_STACKSIZE_MAIN=1092

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include

# Set a custom channel if needed
ifneq (,$(filter cc110x,$(USEMODULE)))          # radio is cc110x sub-GHz
  DEFAULT_CHANNEL ?= 0
  CFLAGS += -DCC110X_DEFAULT_CHANNEL=$(DEFAULT_CHANNEL)
else
  ifneq (,$(filter at86rf212b,$(USEMODULE)))    # radio is IEEE 802.15.4 sub-GHz
    DEFAULT_CHANNEL ?= 5
    CFLAGS += -DIEEE802154_DEFAULT_SUBGHZ_CHANNEL=$(DEFAULT_CHANNEL)
  else                                          # radio is IEEE 802.15.4 2.4 GHz
    DEFAULT_CHANNEL ?= 26
    CFLAGS += -DIEEE802154_DEFAULT_CHANNEL=$(DEFAULT_CHANNEL)
  endif
endif
