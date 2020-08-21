KMOD=	if_sume_v2
SRCS=	if_sume_v2.c
SRCS+=  device_if.h bus_if.h pci_if.h

.include <bsd.kmod.mk>
