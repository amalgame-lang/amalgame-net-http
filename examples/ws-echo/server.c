#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "_runtime.h"
#include "Amalgame_String.h"
#include "Amalgame_Collections.h"
#include "Amalgame_IO.h"
#include "Amalgame_Net.h"
#include "Amalgame_Console.h"
#include "Amalgame_Process.h"

typedef struct _App_Program App_Program;

App_Program* App_Program_new();
void App_Program_Main(code_string* args);
typedef struct LamEnv_0 {
    char _empty;
} LamEnv_0;
static void* lam_0_fn(void* __envRaw, void* __arg0);
struct _App_Program {
};

void App_Program_Main(code_string* args);

App_Program* App_Program_new() {
    App_Program* self = (App_Program*) GC_MALLOC(sizeof(App_Program));
    return self;
}

void App_Program_Main(code_string* args) {
    #line 16 "server.am"
    Console_WriteLine("=== WebSocket echo demo ===");
    #line 17 "server.am"
    Console_WriteLine("Open examples/ws-echo/client.html in your browser.");
    #line 18 "server.am"
    Console_WriteLine("");
    #line 20 "server.am"
    LamEnv_0* __env_0 = (LamEnv_0*) code_alloc(sizeof(LamEnv_0));
    AmalgameClosure* handler = AmalgameClosure_new((void*)lam_0_fn, __env_0);
    #line 34 "server.am"
    App_Ws_Serve(8080, handler);
}

static void* lam_0_fn(void* __envRaw, void* __arg0) {
    LamEnv_0* __env = (LamEnv_0*)__envRaw;
    i64 conn = (i64)(intptr_t)__arg0;
    #line 21 "server.am"
    Console_WriteLine("[ws] client connected");
    #line 22 "server.am"
    while (!App_WsConn_IsClosed(conn)) {
        #line 23 "server.am"
        code_string msg = App_WsConn_ReceiveText(conn);
        #line 24 "server.am"
        if (String_Length(msg) == 0) {
            #line 25 "server.am"
            Console_WriteLine("[ws] client disconnected");
            #line 26 "server.am"
            return (void*)(intptr_t)(0);
        }
        #line 28 "server.am"
        Console_WriteLine(code_string_concat("[ws] recv: ", msg));
        #line 29 "server.am"
        App_WsConn_SendText(conn, code_string_concat("echo @ ", msg));
    }
    #line 31 "server.am"
    return (void*)(intptr_t)(0);
    return (void*)(intptr_t)(0);
}

int main(int argc, char** argv) {
    GC_INIT();
    code_runtime_init_args(argc, argv);
    App_Program_Main((code_string*)argv);
    return code_exit_code;
}
