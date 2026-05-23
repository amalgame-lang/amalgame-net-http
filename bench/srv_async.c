#include "Amalgame_Net_Http.h"
#include <stdio.h>

static void* handler_fn(void* env, void* arg) {
    (void) env;
    AmalgameH1Conn* c = (AmalgameH1Conn*) arg;
    /* I/O-bound simulation: 100ms via FIBER SLEEP — parks the
     * fiber, scheduler advances another concurrent connection. */
    Amalgame_Async_FiberSleep(100);
    Amalgame_Net_Http_H1Conn_Respond(c, 200, "text/plain", "ok");
    return NULL;
}
int main(void) {
    GC_INIT();
    AmalgameClosure* h = AmalgameClosure_new((void*) handler_fn, NULL);
    Amalgame_Net_Http_Http1_ServeAsync(8082, h);
    return 0;
}
