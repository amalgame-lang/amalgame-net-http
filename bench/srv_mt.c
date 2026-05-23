#include "Amalgame_Net_Http.h"
#include <stdio.h>
#include <time.h>

static void* handler_fn(void* env, void* arg) {
    (void) env;
    AmalgameH1Conn* c = (AmalgameH1Conn*) arg;
    /* I/O-bound simulation: 100ms of blocking work (one OS
     * thread per connection in ServeMt). */
    struct timespec ts = { 0, 100 * 1000 * 1000L };
    nanosleep(&ts, NULL);
    Amalgame_Net_Http_H1Conn_Respond(c, 200, "text/plain", "ok");
    return NULL;
}
int main(void) {
    GC_INIT();
    AmalgameClosure* h = AmalgameClosure_new((void*) handler_fn, NULL);
    Amalgame_Net_Http_Http1_ServeMt(8081, h);
    return 0;
}
