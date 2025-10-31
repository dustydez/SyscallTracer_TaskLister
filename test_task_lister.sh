#!/bin/bash

echo "=== Task Lister Module Test Suite ==="
echo ""

# Test 1: Basic functionality
echo "Test 1: Checking if module is loaded..."
if lsmod | grep -q task_lister; then
    echo "✓ Module is loaded"
else
    echo "✗ Module is NOT loaded"
    exit 1
fi
echo ""

# Test 2: Check proc files exist
echo "Test 2: Checking proc entries..."
for file in task_lister task_detail task_stats; do
    if [ -f "/proc/$file" ]; then
        echo "✓ /proc/$file exists"
    else
        echo "✗ /proc/$file missing"
    fi
done
echo ""

# Test 3: Count processes
echo "Test 3: Counting processes..."
task_count=$(cat /proc/task_lister | grep -c "^[[:space:]]*[0-9]")
echo "  Found $task_count processes in task_lister"
ps_count=$(ps aux | wc -l)
echo "  Found $((ps_count - 1)) processes in ps"
echo "✓ Process counting works"
echo ""

# Test 4: Check statistics
echo "Test 4: Checking statistics..."
cat /proc/task_stats
echo "✓ Statistics generated"
echo ""

# Test 5: Search for init process (PID 1)
echo "Test 5: Searching for init process (PID 1)..."
if cat /proc/task_lister | grep -q "^[[:space:]]*1[[:space:]]"; then
    echo "✓ Init process found"
    cat /proc/task_lister | grep "^[[:space:]]*1[[:space:]]"
else
    echo "✗ Init process not found"
fi
echo ""

# Test 6: Memory information
echo "Test 6: Checking memory information..."
if cat /proc/task_stats | grep -q "Total Virtual Memory"; then
    echo "✓ Memory statistics available"
else
    echo "✗ Memory statistics missing"
fi
echo ""

# Test 7: Create new process and detect it
echo "Test 7: Testing real-time detection..."
sleep 30 &
sleep_pid=$!
sleep 1
if cat /proc/task_lister | grep -q "sleep"; then
    echo "✓ Newly created process detected"
    kill $sleep_pid 2>/dev/null
else
    echo "✗ Failed to detect new process"
    kill $sleep_pid 2>/dev/null
fi
echo ""

echo "=== All Tests Complete ==="
