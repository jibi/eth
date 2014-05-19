#include <pico_stack.h>
#include <eth/engine.h>

int
main(int argc, char *argv[]) {
	init_pico_device();

	setup_tcp_app();

	pico_stack_loop();

	return 0;
}

