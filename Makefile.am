bin_PROGRAMS = gbridge

gbridge_CFLAGS = -Wall -Werror -I${GBDIR}
gbridge_LDLIBS =

gbridge_SOURCES = main.c \
		  debug.c \
		  greybus.c \
		  controller.c \
		  protocols/svc.c

if NETLINK
gbridge_SOURCES += controllers/gb_netlink.c
gbridge_CFLAGS += `pkg-config --cflags libnl-3.0 libnl-genl-3.0`
endif

if TPCIP
gbridge_SOURCES += controllers/tcpip.c
gbridge_CFLAGS += `pkg-config --cflags avahi-client`
gbridge_LDLIBS += `pkg-config --libs avahi-client`
endif

if TLS
gbridge_SOURCES += controllers/tls.c
gbridge_CFLAGS += `pkg-config --cflags openssl`
gbridge_LDLIBS += `pkg-config --libs openssl`
endif

if BLUETOOTH
gbridge_SOURCES += controllers/bluetooth.c
gbridge_CFLAGS += `pkg-config --cflags bluez`
endif

if UART
gbridge_SOURCES += controllers/uart.c
endif

if GBSIM
gbridge_SOURCES += controllers/gbsim.c
gbridge_SOURCES += protocols/manifest.c
gbridge_SOURCES += protocols/control.c
gbridge_SOURCES += protocols/loopback.c
endif
