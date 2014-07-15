#include <stdint.h>
#include <glib.h>

uint32_t murmur_hash( const void * key, int len, uint32_t seed );
guint hash_tcp_conn(gconstpointer t);
gboolean cmp_tcp_conn(gconstpointer t1, gconstpointer t2);

