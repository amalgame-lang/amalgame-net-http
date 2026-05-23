"""Concurrent HTTP client that fires N requests in parallel via asyncio.

Outputs:
  elapsed_ms <total wall clock>
  ok <2xx count>
  fail <other count>
"""
import asyncio, sys, time, socket

async def one(host, port):
    try:
        r, w = await asyncio.open_connection(host, port)
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        await w.drain()
        # read until close
        data = await asyncio.wait_for(r.read(4096), timeout=30)
        w.close()
        try: await w.wait_closed()
        except: pass
        return data.startswith(b"HTTP/1.1 200")
    except Exception:
        return False

async def main(host, port, n):
    t0 = time.time()
    results = await asyncio.gather(*[one(host, port) for _ in range(n)])
    t1 = time.time()
    ok = sum(1 for r in results if r)
    print(f"elapsed_ms={int((t1-t0)*1000)} ok={ok} fail={n-ok}")

if __name__ == "__main__":
    host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    # bump ulimit for sockets
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE, (8192, 8192))
    asyncio.run(main(host, port, n))
