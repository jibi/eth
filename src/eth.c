#include <pico_stack.h>
#include <eth/engine.h>

int
main(int argc, char *argv[]) {
	init_pico_device();

	setup_tcp_app();

	while(1) {
		pico_stack_tick();
		usleep(2000);
	}

	return 0;
}

