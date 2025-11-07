#!/bin/bash

echo "=== System Call Tracer Test Suite ==="
echo ""

# Test 1: File operations
echo "Test 1: File Operations"
touch /tmp/tracer_test.txt
echo "Hello World" > /tmp/tracer_test.txt
cat /tmp/tracer_test.txt > /dev/null
rm /tmp/tracer_test.txt
echo "✓ File operations completed"
echo ""

# Test 2: Directory operations
echo "Test 2: Directory Operations"
mkdir /tmp/tracer_testdir
ls /tmp/tracer_testdir > /dev/null
rmdir /tmp/tracer_testdir
echo "✓ Directory operations completed"
echo ""

# Test 3: View traced calls
echo "Test 3: Viewing Traced Calls"
echo "Recent system calls:"
cat /proc/syscall_tracer | tail -15
echo ""

echo "=== Test Complete ==="
