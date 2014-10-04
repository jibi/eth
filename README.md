# eth: extreme throughput http daemon.
A specialized web server with userspace TCP/IP stack.

My undergraduate thesis work.

##Installation

### Steps:
clone the repo
```
$ git clone --recursive git@github.com:jibi/eth.git
```
build dependencies (netmap)

```
$ make deps
```

build eth

```
$ make
```

load netmap module
```
# insmod deps/netmap/LINUX/netmap_lin.ko
```

set interface up

```
# ifconfig $if up
```

and start eth server with

```
# ./eth --dev $ifname --mac $ifmac --ip $ifip --port $port
```

