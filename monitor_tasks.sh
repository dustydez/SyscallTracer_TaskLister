#!/bin/bash

echo "==================== Task Lister Monitor ===================="
echo ""

# Function to display menu
show_menu() {
    echo "Select an option:"
    echo "1. View all tasks (summary)"
    echo "2. View task statistics"
    echo "3. View detailed task info"
    echo "4. Monitor tasks in real-time"
    echo "5. Search for specific process"
    echo "6. Compare with 'ps' command"
    echo "7. Exit"
    echo -n "Enter choice: "
}

# Function to search for process
search_process() {
    echo -n "Enter process name to search: "
    read proc_name
    echo ""
    echo "Results from Task Lister:"
    cat /proc/task_lister | grep -i "$proc_name"
    echo ""
    echo "Results from system 'ps':"
    ps aux | grep -i "$proc_name" | grep -v grep
}

# Function to compare with ps
compare_with_ps() {
    echo "Task Lister count:"
    task_count=$(cat /proc/task_lister | grep -c "^[0-9]")
    echo "  Processes: $task_count"
    echo ""
    echo "System 'ps' count:"
    ps_count=$(ps aux | wc -l)
    echo "  Processes: $((ps_count - 1))"  # Subtract header
    echo ""
    echo "Note: Counts may differ slightly due to kernel threads visibility"
}

# Main loop
while true; do
    show_menu
    read choice
    echo ""
    
    case $choice in
        1)
            cat /proc/task_lister | less
            ;;
        2)
            cat /proc/task_stats
            echo ""
            read -p "Press Enter to continue..."
            ;;
        3)
            cat /proc/task_detail | less
            ;;
        4)
            echo "Monitoring tasks (Ctrl+C to stop)..."
            watch -n 2 'cat /proc/task_stats'
            ;;
        5)
            search_process
            echo ""
            read -p "Press Enter to continue..."
            ;;
        6)
            compare_with_ps
            echo ""
            read -p "Press Enter to continue..."
            ;;
        7)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid choice!"
            ;;
    esac
    echo ""
done
