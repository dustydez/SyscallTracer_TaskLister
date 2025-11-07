# System Call Tracer & Task Lister

## Overview
This project provides two Linux Kernel Modules (LKMs): a System Call Tracer that intercepts and logs system calls with a dynamic filter mechanism, and a Task Lister that traverses kernel task structures to enumerate all active processes with key metadata via procfs interfaces for user-space consumption.

- System Call Tracer: Uses kprobes to trace selected syscalls, keeps a bounded in-kernel log, supports dynamic user-defined filters, and exposes logs and filter state via /proc/syscall_tracer.
- Task Lister: Iterates processes using for_each_process under RCU read lock, extracts PID, PPID, state, memory (VM/RSS), threads, UID/GID, and exposes summary, detail, and stats via procfs.

Note: The current tracer logs and marks events as “BLOCKED” when a filter matches, but it does not alter syscall execution (i.e., no hard blocking is performed yet).

## Features
System Call Tracer
- Kprobes on syscall entry points (e.g., __x64_sys_openat, __x64_sys_read/write/close, __x64_sys_unlink).
- Circular log buffer with spinlock protection and bounded maximum entries.
- Dynamic filters via procfs write interface (e.g., echo "unlink block" > /proc/syscall_tracer).
- Real-time visibility via /proc/syscall_tracer and monitor.sh.

Task Lister
- Process traversal using for_each_process() with RCU read-side critical sections.
- Extraction of PID, PPID, comm, state, VM/RSS memory, thread count, UID/GID from task_struct.
- Multiple procfs views: /proc/task_lister (summary), /proc/task_detail (per-task detail), /proc/task_stats (aggregate counts and memory sums).

## Repository Structure
A typical layout (adjust per repo organization) follows:
- syscall_tracer/
  - syscall_tracer.c — Kernel module source for the syscall tracer.
  - Makefile — Kbuild makefile for building the module.
  - monitor.sh — Real-time procfs/dmesg monitor loop.
  - test_tracer.sh — Script to generate file operations and verify logs.
- task_lister/
  - task_lister.c — Kernel module source for the task lister.
  - Makefile — Kbuild makefile for building the module.
  - monitor_tasks.sh — Real-time stats monitoring helper.
  - test_task_lister.sh — Verification script for listing and stats.

## Prerequisites
- Ubuntu VM with kernel headers: linux-headers-$(uname -r).
- Build tools: make, gcc.
- Kernel config options: CONFIG_KPROBES=y, CONFIG_PROC_FS=y, CONFIG_MODULES=y (CONFIG_DEBUG_INFO recommended).
- Root privileges for insmod/rmmod/read dmesg (or relax dmesg restrictions if desired).

## Build
From each module directory (e.g., syscall_tracer or task_lister):
- make — builds .ko using Kbuild.
- make clean — cleans artifacts.

Example:
- cd syscall_tracer && make && ls -lh syscall_tracer.ko.
- cd ../task_lister && make && ls -lh task_lister.ko.

## Expected Outputs
System Call Tracer (excerpt):
- Table of Syscall, PID, Timestamp (jiffies), and Status (ALLOWED/BLOCKED), followed by “Active Filters.”
- dmesg lines “syscall_tracer: Blocked <syscall>() from PID <n>” when a matching filter is set.

Task Lister (summary):
- Tabular columns: PID, PPID, COMMAND, STATE, VM(KB), RSS(KB), THREADS, UID, GID.
- /proc/task_stats shows counts by state and total VM/RSS (MB).

## Security and Limitations
- Tracer does not modify syscall behavior; “blocked” is an audit label for now.
- Out-of-tree modules will taint the kernel; this is expected for development modules.
- Kprobe symbol names may vary by kernel; adjust symbols if registration fails (check /proc/kallsyms).

## Troubleshooting
- Missing /proc entries: verify module inserted (lsmod), check dmesg for errors, ensure CONFIG_PROC_FS=y.
- Kprobe registration failure: confirm symbol names exist in /proc/kallsyms; kernel versions differ in syscall symbol naming.
- dmesg permission errors: use sudo dmesg or relax kernel.dmesg_restrict for development sessions.

## Build & Run Quick Reference
System Call Tracer (from syscall_tracer/):
- make && sudo insmod syscall_tracer.ko && cat /proc/syscall_tracer.
- echo "write block" | sudo tee /proc/syscall_tracer.
- ./test_tracer.sh && ./monitor.sh.
- sudo rmmod syscall_tracer.

Task Lister (from task_lister/):
- make && sudo insmod task_lister.ko && cat /proc/task_lister.
- cat /proc/task_detail && cat /proc/task_stats.
- ./test_task_lister.sh && ./monitor_tasks.sh.
- sudo rmmod task_lister.

## Future Enhancements
- True syscall blocking (alter return path) via safe mechanisms (e.g., LSM or supported trace frameworks) instead of audit-only labeling.
- Sysfs or netlink interface for structured, programmatic access and event streaming.
- Web dashboard with a user-space daemon for real-time visualization and historical analysis.

## References
- Silberschatz, Abraham, Peter B. Galvin, and Greg Gagne. Operating System Concepts, 10th Edition. Wiley, 2018.
- https://github.com/abhinavpathania/SystemCallTracer
- https://github.com/yoyozaemon/OS-Task-Lister-using-Kernel-Module
