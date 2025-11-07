#!/bin/bash

echo "System Call Tracer Performance Monitor"
echo "======================================"

while true; do
    clear
    echo "Timestamp: $(date)"
    echo ""
    echo "Module Status:"
    lsmod | grep syscall_tracer
    echo ""
    echo "Recent Traced Calls (Last 10):"
    cat /proc/syscall_tracer | tail -10
    echo ""
    echo "Press Ctrl+C to exit"
    sleep 2
done
