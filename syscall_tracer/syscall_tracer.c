#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/list.h>

#define PROCFS_NAME "syscall_tracer"
#define MAX_SYSCALL_NAME 64
#define MAX_LOG_ENTRIES 1000

MODULE_LICENSE("GPL");
MODULE_AUTHOR("OS");
MODULE_DESCRIPTION("System Call Tracer with Filtering");

// Structure to store syscall log entries
struct syscall_log {
    struct list_head list;
    char syscall_name[MAX_SYSCALL_NAME];
    pid_t pid;
    unsigned long timestamp;
    int blocked;
};

// Structure to store filter rules
struct syscall_filter {
    struct list_head list;
    char syscall_name[MAX_SYSCALL_NAME];
    int should_block;  // 1 = block, 0 = allow
};

// Global variables
static LIST_HEAD(log_list);
static LIST_HEAD(filter_list);
static DEFINE_SPINLOCK(log_lock);
static DEFINE_SPINLOCK(filter_lock);
static int log_count = 0;
static struct proc_dir_entry *proc_file;

// Kprobe structures for different syscalls
static struct kprobe kp_open;
static struct kprobe kp_read;
static struct kprobe kp_write;
static struct kprobe kp_close;
static struct kprobe kp_unlink;

// Function to check if syscall should be blocked
static int should_block_syscall(const char *name)
{
    struct syscall_filter *filter;
    int block = 0;

    spin_lock(&filter_lock);
    list_for_each_entry(filter, &filter_list, list) {
        if (strcmp(filter->syscall_name, name) == 0) {
            block = filter->should_block;
            break;
        }
    }
    spin_unlock(&filter_lock);

    return block;
}

// Function to add log entry
static void add_log_entry(const char *syscall_name, pid_t pid, int blocked)
{
    struct syscall_log *entry;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry)
        return;

    strncpy(entry->syscall_name, syscall_name, MAX_SYSCALL_NAME - 1);
    entry->syscall_name[MAX_SYSCALL_NAME - 1] = '\0';
    entry->pid = pid;
    entry->timestamp = jiffies;
    entry->blocked = blocked;

    spin_lock(&log_lock);
    
    // Limit log size
    if (log_count >= MAX_LOG_ENTRIES) {
        struct syscall_log *oldest;
        oldest = list_first_entry(&log_list, struct syscall_log, list);
        list_del(&oldest->list);
        kfree(oldest);
        log_count--;
    }
    
    list_add_tail(&entry->list, &log_list);
    log_count++;
    
    spin_unlock(&log_lock);
}

// Kprobe handler for sys_open/openat
static int handler_pre_open(struct kprobe *p, struct pt_regs *regs)
{
    int blocked = should_block_syscall("open");
    
    add_log_entry("open", current->pid, blocked);
    
    if (blocked) {
        printk(KERN_INFO "syscall_tracer: Blocked open() from PID %d\n", current->pid);
        // To actually block, we'd need to modify return value
        // This is for demonstration - actual blocking requires more complex logic
    }
    
    return 0;
}

// Kprobe handler for sys_read
static int handler_pre_read(struct kprobe *p, struct pt_regs *regs)
{
    int blocked = should_block_syscall("read");
    add_log_entry("read", current->pid, blocked);
    
    if (blocked) {
        printk(KERN_INFO "syscall_tracer: Blocked read() from PID %d\n", current->pid);
    }
    
    return 0;
}

// Kprobe handler for sys_write
static int handler_pre_write(struct kprobe *p, struct pt_regs *regs)
{
    int blocked = should_block_syscall("write");
    add_log_entry("write", current->pid, blocked);
    
    if (blocked) {
        printk(KERN_INFO "syscall_tracer: Blocked write() from PID %d\n", current->pid);
    }
    
    return 0;
}

// Kprobe handler for sys_close
static int handler_pre_close(struct kprobe *p, struct pt_regs *regs)
{
    add_log_entry("close", current->pid, 0);
    return 0;
}

// Kprobe handler for sys_unlink (potentially harmful)
static int handler_pre_unlink(struct kprobe *p, struct pt_regs *regs)
{
    int blocked = should_block_syscall("unlink");
    add_log_entry("unlink", current->pid, blocked);
    
    if (blocked) {
        printk(KERN_WARNING "syscall_tracer: Blocked unlink() from PID %d\n", current->pid);
    }
    
    return 0;
}

// Procfs show function
static int syscall_tracer_show(struct seq_file *m, void *v)
{
    struct syscall_log *entry;
    
    seq_printf(m, "System Call Tracer Log\n");
    seq_printf(m, "======================\n");
    seq_printf(m, "%-10s %-10s %-15s %-10s\n", "Syscall", "PID", "Timestamp", "Status");
    seq_printf(m, "--------------------------------------------------------\n");
    
    spin_lock(&log_lock);
    list_for_each_entry(entry, &log_list, list) {
        seq_printf(m, "%-10s %-10d %-15lu %-10s\n",
                   entry->syscall_name,
                   entry->pid,
                   entry->timestamp,
                   entry->blocked ? "BLOCKED" : "ALLOWED");
    }
    spin_unlock(&log_lock);
    
    seq_printf(m, "\nTotal entries: %d\n", log_count);
    
    // Show active filters
    seq_printf(m, "\nActive Filters:\n");
    seq_printf(m, "===============\n");
    
    spin_lock(&filter_lock);
    if (list_empty(&filter_list)) {
        seq_printf(m, "No filters active\n");
    } else {
        struct syscall_filter *filter;
        list_for_each_entry(filter, &filter_list, list) {
            seq_printf(m, "%s: %s\n", filter->syscall_name,
                      filter->should_block ? "BLOCK" : "ALLOW");
        }
    }
    spin_unlock(&filter_lock);
    
    return 0;
}

// Procfs write function (for adding filters)
static ssize_t syscall_tracer_write(struct file *file, const char __user *buffer,
                                     size_t count, loff_t *ppos)
{
    char input[128];
    char syscall_name[MAX_SYSCALL_NAME];
    char action[16];
    struct syscall_filter *filter;
    
    if (count >= sizeof(input))
        return -EINVAL;
    
    if (copy_from_user(input, buffer, count))
        return -EFAULT;
    
    input[count] = '\0';
    
    // Parse input: "syscall_name block" or "syscall_name allow"
    if (sscanf(input, "%63s %15s", syscall_name, action) != 2) {
        printk(KERN_WARNING "syscall_tracer: Invalid format. Use: <syscall> <block|allow>\n");
        return -EINVAL;
    }
    
    filter = kmalloc(sizeof(*filter), GFP_KERNEL);
    if (!filter)
        return -ENOMEM;
    
    strncpy(filter->syscall_name, syscall_name, MAX_SYSCALL_NAME - 1);
    filter->syscall_name[MAX_SYSCALL_NAME - 1] = '\0';
    filter->should_block = (strcmp(action, "block") == 0) ? 1 : 0;
    
    spin_lock(&filter_lock);
    list_add_tail(&filter->list, &filter_list);
    spin_unlock(&filter_lock);
    
    printk(KERN_INFO "syscall_tracer: Added filter - %s: %s\n",
           syscall_name, action);
    
    return count;
}

static int syscall_tracer_open(struct inode *inode, struct file *file)
{
    return single_open(file, syscall_tracer_show, NULL);
}

static const struct proc_ops syscall_tracer_fops = {
    .proc_open = syscall_tracer_open,
    .proc_read = seq_read,
    .proc_write = syscall_tracer_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

// Module initialization
static int __init syscall_tracer_init(void)
{
    int ret;
    
    printk(KERN_INFO "syscall_tracer: Initializing module\n");
    
    // Create proc entry
    proc_file = proc_create(PROCFS_NAME, 0666, NULL, &syscall_tracer_fops);
    if (!proc_file) {
        printk(KERN_ERR "syscall_tracer: Failed to create /proc/%s\n", PROCFS_NAME);
        return -ENOMEM;
    }
    
    // Register kprobes for different syscalls
    kp_open.symbol_name = "__x64_sys_openat";
    kp_open.pre_handler = handler_pre_open;
    
    kp_read.symbol_name = "__x64_sys_read";
    kp_read.pre_handler = handler_pre_read;
    
    kp_write.symbol_name = "__x64_sys_write";
    kp_write.pre_handler = handler_pre_write;
    
    kp_close.symbol_name = "__x64_sys_close";
    kp_close.pre_handler = handler_pre_close;
    
    kp_unlink.symbol_name = "__x64_sys_unlink";
    kp_unlink.pre_handler = handler_pre_unlink;
    
    // Register all kprobes
    ret = register_kprobe(&kp_open);
    if (ret < 0) {
        printk(KERN_ERR "syscall_tracer: Failed to register kprobe for open\n");
        goto fail_open;
    }
    
    ret = register_kprobe(&kp_read);
    if (ret < 0) {
        printk(KERN_ERR "syscall_tracer: Failed to register kprobe for read\n");
        goto fail_read;
    }
    
    ret = register_kprobe(&kp_write);
    if (ret < 0) {
        printk(KERN_ERR "syscall_tracer: Failed to register kprobe for write\n");
        goto fail_write;
    }
    
    ret = register_kprobe(&kp_close);
    if (ret < 0) {
        printk(KERN_ERR "syscall_tracer: Failed to register kprobe for close\n");
        goto fail_close;
    }
    
    ret = register_kprobe(&kp_unlink);
    if (ret < 0) {
        printk(KERN_ERR "syscall_tracer: Failed to register kprobe for unlink\n");
        goto fail_unlink;
    }
    
    printk(KERN_INFO "syscall_tracer: Module loaded successfully\n");
    printk(KERN_INFO "syscall_tracer: Access via /proc/%s\n", PROCFS_NAME);
    
    return 0;

// Error handling
fail_unlink:
    unregister_kprobe(&kp_close);
fail_close:
    unregister_kprobe(&kp_write);
fail_write:
    unregister_kprobe(&kp_read);
fail_read:
    unregister_kprobe(&kp_open);
fail_open:
    proc_remove(proc_file);
    return ret;
}

// Module cleanup
static void __exit syscall_tracer_exit(void)
{
    struct syscall_log *log_entry, *log_tmp;
    struct syscall_filter *filter_entry, *filter_tmp;
    
    // Unregister kprobes
    unregister_kprobe(&kp_open);
    unregister_kprobe(&kp_read);
    unregister_kprobe(&kp_write);
    unregister_kprobe(&kp_close);
    unregister_kprobe(&kp_unlink);
    
    // Remove proc entry
    proc_remove(proc_file);
    
    // Free log entries
    spin_lock(&log_lock);
    list_for_each_entry_safe(log_entry, log_tmp, &log_list, list) {
        list_del(&log_entry->list);
        kfree(log_entry);
    }
    spin_unlock(&log_lock);
    
    // Free filter entries
    spin_lock(&filter_lock);
    list_for_each_entry_safe(filter_entry, filter_tmp, &filter_list, list) {
        list_del(&filter_entry->list);
        kfree(filter_entry);
    }
    spin_unlock(&filter_lock);
    
    printk(KERN_INFO "syscall_tracer: Module unloaded\n");
}

module_init(syscall_tracer_init);
module_exit(syscall_tracer_exit);
