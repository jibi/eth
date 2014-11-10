# eth: extreme throughput http daemon.
A specialized web server with userspace TCP/IP stack.

My undergraduate thesis work.

##Installation

### Steps:
clone the repo
```
$ git clone --recursive git@github.com:jibi/eth.git
```
build dependencies (Netmap).

Note: you need the kernel sources of your running kernel to be in the
`/usr/src/linux` directory.

```
$ make deps
```

build eth

```
$ make
```

load netmap module
```
# insmod deps/netmap/LINUX/netmap.ko
```

set interface up

```
# ifconfig $if up
```

and start eth server with

```
# ./eth --dev $ifname --mac $ifmac --ip $ifip --port $port
```

