# eth: extreme throughput http daemon.
A specialized web server with userspace TCP/IP stack.

My undergraduate thesis work.

##Installation
### Deps:

* rake
* clang
* ragel

### Steps:
clone the repo
```
$ git clone --recursive git@github.com:jibi/eth.git
```

build dependencies (picotcp and netmap)

```
$ rake deps
```
setup eth (set the right interface and its mac and ip address in `init_pico_engine()` in engine.c)

```C
void
init_pico_device() {
  /* change macaddr with the real interface address */
	unsigned char macaddr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

/* .. */

  /* set right interface name and address */
	dev = pico_netmap_create(IF_NAME, "eth_if", macaddr);
	pico_string_to_ipv4(IF_ADDR, &addr.addr);
	pico_string_to_ipv4("255.255.255.0", &netmask.addr);
	pico_ipv4_link_add(dev, addr, netmask);

}
```

build eth

```
$ rake
```

load netmap module
```
# insmod deps/netmap/LINUX/netmap_lin.ko
```

set interface up

```
# ifconfig $if up
```

and start eth server

```
# ./eth
```

### Testing
eth serves files under the htdocs directory.

Moreover it responds to /autism GET request with the request parameters.

