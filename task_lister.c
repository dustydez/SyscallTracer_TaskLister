#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define PROCFS_NAME "task_lister"
#define MAX_TASKS 5000

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Linux Kernel Task Lister - Traverses and displays all active processes");
MODULE_VERSION("1.0");

static struct proc_dir_entry *proc_file;

// Structure to cache task information
struct task_info {
    pid_t pid;
    pid_t ppid;
    char comm[TASK_COMM_LEN];
    long state;
    unsigned long total_vm;  // Total virtual memory (pages)
    unsigned long rss;        // Resident set size (pages)
    int num_threads;
    uid_t uid;
    gid_t gid;
};

// Function to get process state as string
static const char *get_task_state_string(long state)
{
    switch (state) {
        case TASK_RUNNING:
            return "RUNNING";
        case TASK_INTERRUPTIBLE:
            return "SLEEPING";
        case TASK_UNINTERRUPTIBLE:
            return "DISK_SLEEP";
        case __TASK_STOPPED:
            return "STOPPED";
        case __TASK_TRACED:
            return "TRACED";
        case EXIT_DEAD:
            return "DEAD";
        case EXIT_ZOMBIE:
            return "ZOMBIE";
        default:
            return "UNKNOWN";
    }
}

// Function to get memory info from task_struct
static void get_memory_info(struct task_struct *task, unsigned long *vm, unsigned long *rss)
{
    struct mm_struct *mm;
    
    *vm = 0;
    *rss = 0;
    
    mm = get_task_mm(task);
    if (mm) {
        *vm = mm->total_vm;  // Total virtual memory in pages
        *rss = get_mm_rss(mm); // Resident set size in pages
        mmput(mm);
    }
}

// Function to get UID of task
static uid_t get_task_uid(struct task_struct *task)
{
    const struct cred *cred;
    uid_t uid = 0;
    
    rcu_read_lock();
    cred = __task_cred(task);
    if (cred)
        uid = cred->uid.val;
    rcu_read_unlock();
    
    return uid;
}

// Function to get GID of task
static gid_t get_task_gid(struct task_struct *task)
{
    const struct cred *cred;
    gid_t gid = 0;
    
    rcu_read_lock();
    cred = __task_cred(task);
    if (cred)
        gid = cred->gid.val;
    rcu_read_unlock();
    
    return gid;
}

// Procfs show function - displays all tasks
static int task_lister_show(struct seq_file *m, void *v)
{
    struct task_struct *task;
    int task_count = 0;
    unsigned long total_vm, rss;
    pid_t ppid;
    
    seq_printf(m, "==================== LINUX KERNEL TASK LISTER ====================\n");
    seq_printf(m, "%-8s %-8s %-20s %-12s %-10s %-10s %-8s %-8s %-8s\n",
               "PID", "PPID", "COMMAND", "STATE", "VM(KB)", "RSS(KB)", "THREADS", "UID", "GID");
    seq_printf(m, "==================================================================");
    seq_printf(m, "==================================================================\n");
    
    // Traverse all processes using for_each_process macro
    rcu_read_lock();
    for_each_process(task) {
        // Get parent PID
        ppid = task->real_parent ? task_pid_nr(task->real_parent) : 0;
        
        // Get memory information
        get_memory_info(task, &total_vm, &rss);
        
        // Display task information
        seq_printf(m, "%-8d %-8d %-20s %-12s %-10lu %-10lu %-8d %-8u %-8u\n",
                   task_pid_nr(task),                    // PID
                   ppid,                                  // Parent PID
                   task->comm,                            // Command name
                   get_task_state_string(task->__state),  // State
                   (total_vm * PAGE_SIZE) / 1024,        // VM in KB
                   (rss * PAGE_SIZE) / 1024,             // RSS in KB
                   task->signal ? atomic_read(&task->signal->live) : 1, // Threads
                   get_task_uid(task),                   // UID
                   get_task_gid(task));                  // GID
        
        task_count++;
        
        // Prevent overwhelming output
        if (task_count >= MAX_TASKS) {
            seq_printf(m, "\n[Output truncated - max %d tasks displayed]\n", MAX_TASKS);
            break;
        }
    }
    rcu_read_unlock();
    
    seq_printf(m, "==================================================================");
    seq_printf(m, "==================================================================\n");
    seq_printf(m, "Total processes listed: %d\n", task_count);
    seq_printf(m, "Page size: %lu bytes\n", PAGE_SIZE);
    
    return 0;
}

// Function to show detailed info about a specific PID
static int task_detail_show(struct seq_file *m, void *v)
{
    struct task_struct *task;
    unsigned long total_vm, rss;
    
    seq_printf(m, "==================== DETAILED TASK INFORMATION ====================\n\n");
    
    rcu_read_lock();
    for_each_process(task) {
        get_memory_info(task, &total_vm, &rss);
        
        seq_printf(m, "PID: %d\n", task_pid_nr(task));
        seq_printf(m, "  Command: %s\n", task->comm);
        seq_printf(m, "  State: %s\n", get_task_state_string(task->__state));
        seq_printf(m, "  Parent PID: %d\n", 
                   task->real_parent ? task_pid_nr(task->real_parent) : 0);
        seq_printf(m, "  UID: %u, GID: %u\n", get_task_uid(task), get_task_gid(task));
        seq_printf(m, "  Virtual Memory: %lu KB\n", (total_vm * PAGE_SIZE) / 1024);
        seq_printf(m, "  Resident Memory (RSS): %lu KB\n", (rss * PAGE_SIZE) / 1024);
        seq_printf(m, "  Number of Threads: %d\n",
                   task->signal ? atomic_read(&task->signal->live) : 1);
        seq_printf(m, "  Priority: %d\n", task->prio);
        seq_printf(m, "  Nice Value: %d\n", task_nice(task));
        seq_printf(m, "  CPU: %d\n", task_cpu(task));
        seq_printf(m, "\n");
    }
    rcu_read_unlock();
    
    return 0;
}

// Function to count tasks by state
static int task_stats_show(struct seq_file *m, void *v)
{
    struct task_struct *task;
    int running = 0, sleeping = 0, stopped = 0, zombie = 0, other = 0;
    unsigned long total_vm = 0, total_rss = 0;
    unsigned long task_vm, task_rss;
    
    seq_printf(m, "==================== TASK STATISTICS ====================\n\n");
    
    rcu_read_lock();
    for_each_process(task) {
        // Count by state
        switch (task->__state) {
            case TASK_RUNNING:
                running++;
                break;
            case TASK_INTERRUPTIBLE:
                sleeping++;
                break;
            case __TASK_STOPPED:
            case __TASK_TRACED:
                stopped++;
                break;
            case EXIT_ZOMBIE:
                zombie++;
                break;
            default:
                other++;
                break;
        }
        
        // Accumulate memory
        get_memory_info(task, &task_vm, &task_rss);
        total_vm += task_vm;
        total_rss += task_rss;
    }
    rcu_read_unlock();
    
    seq_printf(m, "Process States:\n");
    seq_printf(m, "  Running:     %d\n", running);
    seq_printf(m, "  Sleeping:    %d\n", sleeping);
    seq_printf(m, "  Stopped:     %d\n", stopped);
    seq_printf(m, "  Zombie:      %d\n", zombie);
    seq_printf(m, "  Other:       %d\n", other);
    seq_printf(m, "  Total:       %d\n", running + sleeping + stopped + zombie + other);
    seq_printf(m, "\n");
    seq_printf(m, "Memory Usage:\n");
    seq_printf(m, "  Total Virtual Memory: %lu MB\n", (total_vm * PAGE_SIZE) / (1024 * 1024));
    seq_printf(m, "  Total RSS:            %lu MB\n", (total_rss * PAGE_SIZE) / (1024 * 1024));
    seq_printf(m, "\n");
    
    return 0;
}

static int task_lister_open(struct inode *inode, struct file *file)
{
    return single_open(file, task_lister_show, NULL);
}

static int task_detail_open(struct inode *inode, struct file *file)
{
    return single_open(file, task_detail_show, NULL);
}

static int task_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, task_stats_show, NULL);
}

static const struct proc_ops task_lister_fops = {
    .proc_open = task_lister_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static const struct proc_ops task_detail_fops = {
    .proc_open = task_detail_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static const struct proc_ops task_stats_fops = {
    .proc_open = task_stats_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

// Module initialization
static int __init task_lister_init(void)
{
    printk(KERN_INFO "task_lister: Initializing Task Lister Module\n");
    
    // Create main task list proc entry
    proc_file = proc_create("task_lister", 0444, NULL, &task_lister_fops);
    if (!proc_file) {
        printk(KERN_ERR "task_lister: Failed to create /proc/task_lister\n");
        return -ENOMEM;
    }
    
    // Create detailed task info proc entry
    if (!proc_create("task_detail", 0444, NULL, &task_detail_fops)) {
        printk(KERN_ERR "task_lister: Failed to create /proc/task_detail\n");
        proc_remove(proc_file);
        return -ENOMEM;
    }
    
    // Create task statistics proc entry
    if (!proc_create("task_stats", 0444, NULL, &task_stats_fops)) {
        printk(KERN_ERR "task_lister: Failed to create /proc/task_stats\n");
        remove_proc_entry("task_detail", NULL);
        proc_remove(proc_file);
        return -ENOMEM;
    }
    
    printk(KERN_INFO "task_lister: Module loaded successfully\n");
    printk(KERN_INFO "task_lister: Access via /proc/task_lister\n");
    printk(KERN_INFO "task_lister: Detailed info at /proc/task_detail\n");
    printk(KERN_INFO "task_lister: Statistics at /proc/task_stats\n");
    
    return 0;
}

// Module cleanup
static void __exit task_lister_exit(void)
{
    // Remove all proc entries
    remove_proc_entry("task_stats", NULL);
    remove_proc_entry("task_detail", NULL);
    proc_remove(proc_file);
    
    printk(KERN_INFO "task_lister: Module unloaded\n");
}

module_init(task_lister_init);
module_exit(task_lister_exit);
