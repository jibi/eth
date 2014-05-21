#define HTONS(x) (((x & 0xff00) >> 8) | ((x & 0x00ff) << 8))
#define HTONL(x) (((x & 0xff000000) >> 24) | ((x & 0xff0000) >> 8) | ((x & 0xff00) << 8) | ((x & 0xff) << 24))

void init_yoctonet();
