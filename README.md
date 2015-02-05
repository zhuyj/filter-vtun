# filter-vtun
This will create a subsystem in linux3.19-rc6. This subsystem will clone the packets from a real physical nic(network interface card). According to the filtering rules, the unnecessary packets will not be cloned. Then the cloned packets will be sent to a vtun nic. In this vtun nic, the filtering rules will continue to remove the unnecessary packets.

+-----------------------------------------+
|eth0 --------clone-packets--> vtun0      |
|192.168.6.80                  up         |
+-----------------------------------------+

.
├── interface
│   ├── Makefile
│   └── operate.c
├── README.md
├── read_vtun
│   ├── Makefile
│   └── read_vtun.c
├── vtun
│   ├── Makefile
│   └── vtun.c
└── xt_CLONE
    ├── Makefile
    ├── xt_CLONE.c
    └── xt_CLONE.h

