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

FAQ:
1. How to build this project?
   This project is based on Ubuntu14.04 Desktop. It depends on
   linux kernel 3.19-rc6.
   In this case, please follow these steps:
    a) git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git linux-git
    b) git checkout -f v3.19-rc6
    c) cp /usr/src/linux-headers-3.13.0-44-generic/.config the-directory-kernel/.config
    d) make-kpkg --initrd --append-to-version=-dev kernel_image kernel-headers
    e) dpkg -i *.deb
    f) git clone https://github.com/zhuyj/filter-vtun
    g) cd the-directory-filter-vtun
    h) make

2. What is the final result?
   This tool will generate a pcap file in /tmp/temp.pcap. This temp.pcap is compatible with
   tcpdump and wireshark. We can ananlyze this file by tcpdump or wireshark.
