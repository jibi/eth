void dump(const char *data_buffer, const unsigned int length);
void log_debug1(const char *msg __attribute__((unused)), ...);
void log_debug2(const char *msg __attribute__((unused)), ...);
void log_info(const char *msg, ...);
void log_error(const char *msg, ...);
void fatal_tragedy(int code, const char *msg, ...);
