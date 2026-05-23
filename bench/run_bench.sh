#!/bin/bash
set -u
VARIANT="$1"; PORT="$2"; N="$3"
BENCH=/tmp/bench-async

fuser -k -n tcp "$PORT" 2>/dev/null; sleep 0.2
"$BENCH/srv_$VARIANT" > "$BENCH/$VARIANT.log" 2>&1 &
SPID=$!
sleep 0.5
RSS_IDLE=$(awk '/^VmRSS:/{print $2}' /proc/$SPID/status 2>/dev/null)

# Start the client in background, sample RSS while running
python3 "$BENCH/aclient.py" 127.0.0.1 "$PORT" "$N" > "$BENCH/$VARIANT.client" &
CPID=$!

# Sample RSS every 10ms; keep peak
PEAK=0
while kill -0 $CPID 2>/dev/null; do
    RSS=$(awk '/^VmRSS:/{print $2}' /proc/$SPID/status 2>/dev/null || echo 0)
    [ "$RSS" -gt "$PEAK" ] && PEAK=$RSS
    sleep 0.01
done
wait $CPID
RESULT=$(cat "$BENCH/$VARIANT.client")

echo "variant=$VARIANT N=$N $RESULT rss_idle=${RSS_IDLE}KB rss_peak=${PEAK}KB"

kill -TERM $SPID 2>/dev/null
wait $SPID 2>/dev/null
fuser -k -n tcp "$PORT" 2>/dev/null
sleep 0.2
