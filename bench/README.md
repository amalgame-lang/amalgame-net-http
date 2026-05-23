# ServeMt vs ServeAsync — concurrent-I/O benchmark

Reproduces the table in the top-level README. asyncio HTTP client
fires N concurrent requests at two servers (one per variant), both
with a 100 ms sleeping handler. RSS sampled every 10 ms during the
burst.

## Build

```bash
PKG=$(realpath ..)
ASYNC=$(realpath ../../amalgame-async)        # peer dep, v0.2.0+
AMC_RT=$(realpath ../../Amalgame/runtime)     # main amc runtime

gcc -O2 -I"$PKG/runtime" -I"$AMC_RT" -I"$ASYNC/runtime" \
    srv_mt.c -lgc -lpthread -lssl -lcrypto -lnghttp2 -o srv_mt

gcc -O2 -I"$PKG/runtime" -I"$AMC_RT" -I"$ASYNC/runtime" \
    srv_async.c -lgc -lpthread -lssl -lcrypto -lnghttp2 -o srv_async
```

## Run

```bash
./run_bench.sh mt    8081 1000      # ServeMt at 1000 concurrent conns
./run_bench.sh async 8082 1000      # ServeAsync at 1000
```

The script prints one line per run:

```
variant=async N=1000 elapsed_ms=1628 ok=1000 fail=0 rss_idle=1852KB rss_peak=71484KB
```

## Notes

- `srv_mt.c` uses `nanosleep(100ms)` in the handler — appropriate
  for ServeMt where each connection has its own OS thread.
- `srv_async.c` uses `Amalgame_Async_FiberSleep(100)` — parks the
  fiber, scheduler advances another concurrent connection.
- `aclient.py` uses asyncio + bumped RLIMIT_NOFILE to fire N=2000
  cleanly. xargs+curl can't scale that high without fd-limit
  tuning.
- These binaries are throwaway smoke-tests, NOT shipped as part of
  the package. They live here for benchmark reproducibility.
