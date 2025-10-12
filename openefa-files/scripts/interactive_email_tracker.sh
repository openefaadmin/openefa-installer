#!/bin/bash
##############################################################################
# Interactive Email Tracker
# Purpose: User-friendly interactive email tracking and troubleshooting
##############################################################################

# Colors for better display
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored headers
print_header() {
    echo -e "${CYAN}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Function to show menu
show_menu() {
    clear
    print_header "SpaCy Interactive Email Tracker"
    echo ""
    echo -e "${PURPLE}🔍 What would you like to do?${NC}"
    echo ""
    echo "1) Track emails between sender and receiver"
    echo "2) Track emails from a specific sender"
    echo "3) Track emails to a specific receiver" 
    echo "4) Lookup specific Queue ID"
    echo "5) Monitor live emails (real-time)"
    echo "6) Check Redis error status"
    echo "7) System health check"
    echo "8) Exit"
    echo ""
    echo -n "Select option (1-8): "
}

# Function to get time range
get_time_range() {
    echo ""
    print_info "Time range options:"
    echo "1) Last hour (default)"
    echo "2) Last 4 hours"  
    echo "3) Last 24 hours"
    echo "4) Custom time range"
    echo ""
    echo -n "Select time range (1-4) [1]: "
    read time_choice
    
    case $time_choice in
        2) echo "4 hours ago" ;;
        3) echo "24 hours ago" ;;
        4) 
            echo -n "Enter custom time range (e.g., '2 days ago', '2025-07-09 10:00'): "
            read custom_time
            echo "$custom_time"
            ;;
        *) echo "1 hour ago" ;;
    esac
}

# Function to track emails between sender and receiver
track_sender_receiver() {
    echo ""
    print_header "Track Emails Between Sender and Receiver"
    echo ""
    
    echo -n "Enter sender email or domain (e.g., noreply@example.com or example.com): "
    read sender_input

    echo -n "Enter receiver email (e.g., user@yourdomain.com): "
    read receiver_input
    
    time_range=$(get_time_range)
    
    echo ""
    print_info "Searching for emails from '$sender_input' to '$receiver_input' since $time_range..."
    echo ""
    
    # Search for matching emails
    found_emails=false
    
    # Search in mail.log for matching sender/receiver patterns
    grep_pattern_sender=""
    if [[ "$sender_input" == *"@"* ]]; then
        # Full email address
        grep_pattern_sender="from=<$sender_input>"
    else
        # Domain only
        grep_pattern_sender="@$sender_input>"
    fi
    
    # Get recent log entries and search
    journalctl --since "$time_range" | grep "$grep_pattern_sender" | grep "to=<$receiver_input>" | while read line; do
        found_emails=true
        
        # Extract Queue ID
        queue_id=$(echo "$line" | grep -o '[A-F0-9]\{10,15\}:' | sed 's/://' | head -1)
        timestamp=$(echo "$line" | awk '{print $1, $2, $3}')
        
        if [ -n "$queue_id" ]; then
            echo -e "${GREEN}📧 Found Email:${NC}"
            echo "   Queue ID: $queue_id"
            echo "   Timestamp: $timestamp"
            echo "   From: $sender_input"
            echo "   To: $receiver_input"
            
            # Get processing status
            status_line=$(grep "$queue_id" /var/log/mail.log | grep -E "(status=|relay=)" | tail -1)
            if [ -n "$status_line" ]; then
                if echo "$status_line" | grep "status=sent" > /dev/null; then
                    print_success "   Status: Successfully delivered"
                elif echo "$status_line" | grep "SOFTBOUNCE" > /dev/null; then
                    print_error "   Status: Processing failed (SOFTBOUNCE)"
                elif echo "$status_line" | grep "relay=spacyfilter" > /dev/null; then
                    print_warning "   Status: Being processed by SpaCy filter"
                else
                    print_info "   Status: In progress"
                fi
            fi
            
            echo ""
            echo -n "View detailed logs for this email? (y/n): "
            read view_details
            if [[ "$view_details" =~ ^[Yy] ]]; then
                show_queue_details "$queue_id"
            fi
            echo ""
        fi
    done
    
    # Alternative search in case journalctl doesn't have full history
    print_info "Also checking mail.log directly..."
    grep "$grep_pattern_sender" /var/log/mail.log | grep "to=<$receiver_input>" | tail -5 | while read line; do
        queue_id=$(echo "$line" | grep -o '[A-F0-9]\{10,15\}:' | sed 's/://')
        timestamp=$(echo "$line" | awk '{print $1, $2, $3}')
        
        if [ -n "$queue_id" ]; then
            echo -e "${CYAN}📧 Found in mail.log:${NC}"
            echo "   Queue ID: $queue_id"
            echo "   Timestamp: $timestamp"
            echo ""
        fi
    done
}

# Function to show detailed queue information
show_queue_details() {
    local queue_id="$1"
    
    print_header "Queue ID: $queue_id Details"
    echo ""
    
    print_info "Postfix Processing:"
    grep "$queue_id" /var/log/mail.log | while read line; do
        echo "   $line"
    done
    
    echo ""
    print_info "SpaCy Processing:"
    journalctl | grep "$queue_id" | grep -E "(DEBUG|EMERGENCY|Redis)" | tail -10 | while read line; do
        echo "   $line"
    done
    
    echo ""
    print_info "Final Status:"
    final_status=$(grep "$queue_id" /var/log/mail.log | tail -1)
    echo "   $final_status"
    
    echo ""
}

# Function to track from specific sender
track_from_sender() {
    echo ""
    print_header "Track Emails from Specific Sender"
    echo ""
    
    echo -n "Enter sender email or domain: "
    read sender_input
    
    time_range=$(get_time_range)
    
    echo ""
    print_info "Searching for emails from '$sender_input' since $time_range..."
    echo ""
    
    if [[ "$sender_input" == *"@"* ]]; then
        grep_pattern="from=<$sender_input>"
    else
        grep_pattern="@$sender_input>"
    fi
    
    journalctl --since "$time_range" | grep "$grep_pattern" | head -10 | while read line; do
        queue_id=$(echo "$line" | grep -o '[A-F0-9]\{10,15\}:' | sed 's/://')
        timestamp=$(echo "$line" | awk '{print $1, $2, $3}')
        recipient=$(echo "$line" | grep -o 'to=<[^>]*>' | sed 's/to=<//;s/>//')
        
        if [ -n "$queue_id" ]; then
            echo "📧 Queue ID: $queue_id"
            echo "   Time: $timestamp"
            echo "   To: $recipient"
            echo ""
        fi
    done
}

# Function to track to specific receiver
track_to_receiver() {
    echo ""
    print_header "Track Emails to Specific Receiver"
    echo ""
    
    echo -n "Enter receiver email: "
    read receiver_input
    
    time_range=$(get_time_range)
    
    echo ""
    print_info "Searching for emails to '$receiver_input' since $time_range..."
    echo ""
    
    journalctl --since "$time_range" | grep "to=<$receiver_input>" | head -10 | while read line; do
        queue_id=$(echo "$line" | grep -o '[A-F0-9]\{10,15\}:' | sed 's/://')
        timestamp=$(echo "$line" | awk '{print $1, $2, $3}')
        sender=$(echo "$line" | grep -o 'from=<[^>]*>' | sed 's/from=<//;s/>//')
        
        if [ -n "$queue_id" ]; then
            echo "📧 Queue ID: $queue_id"
            echo "   Time: $timestamp"
            echo "   From: $sender"
            echo ""
        fi
    done
}

# Function to lookup specific Queue ID
lookup_queue_id() {
    echo ""
    print_header "Lookup Specific Queue ID"
    echo ""
    
    echo -n "Enter Queue ID (e.g., 35A571580205): "
    read queue_id_input
    
    if [ -z "$queue_id_input" ]; then
        print_error "No Queue ID provided"
        return
    fi
    
    echo ""
    show_queue_details "$queue_id_input"
    
    echo ""
    echo -n "View raw email content? (y/n): "
    read view_content
    if [[ "$view_content" =~ ^[Yy] ]]; then
        echo ""
        print_info "Raw email content:"
        postcat -q "$queue_id_input" 2>/dev/null || print_error "Queue ID not found in active queue"
    fi
}

# Function to monitor live emails
monitor_live() {
    echo ""
    print_header "Live Email Monitoring"
    echo ""
    print_warning "Starting live monitoring... Press Ctrl+C to stop"
    echo ""
    
    /opt/spacyserver/scripts/live_email_monitor_fixed.sh
}

# Function to check Redis status
check_redis_status() {
    echo ""
    print_header "Redis Error Status Check"
    echo ""
    
    # Check recent Redis errors
    redis_errors_1h=$(journalctl --since "1 hour ago" | grep "non-production format message" | wc -l)
    redis_errors_24h=$(journalctl --since "24 hours ago" | grep "non-production format message" | wc -l)
    
    echo "Redis Queue Errors:"
    echo "   Last hour: $redis_errors_1h"
    echo "   Last 24 hours: $redis_errors_24h"
    
    if [ "$redis_errors_1h" -eq 0 ]; then
        print_success "No Redis errors in the last hour - Emergency fix is working!"
    else
        print_error "Redis errors detected - May need investigation"
    fi
    
    # Check emergency fix status
    echo ""
    emergency_messages=$(journalctl --since "1 hour ago" | grep "EMERGENCY.*Redis disabled" | wc -l)
    echo "Emergency fix activations: $emergency_messages"
    
    if [ "$emergency_messages" -gt 0 ]; then
        print_success "Emergency fix is active"
    else
        print_warning "Emergency fix messages not found in recent logs"
    fi
}

# Function to check system health
check_system_health() {
    echo ""
    print_header "System Health Check"
    echo ""
    
    print_info "SpaCy Email Filter Status:"
    
    # Check if filter is processing emails
    recent_processing=$(journalctl --since "10 minutes ago" | grep "spacyfilter" | wc -l)
    echo "   Recent email processing: $recent_processing emails"
    
    # Check for crashes
    recent_crashes=$(journalctl --since "1 hour ago" | grep "SOFTBOUNCE" | wc -l)
    echo "   Recent crashes: $recent_crashes"
    
    # Check Redis status
    if command -v redis-cli &> /dev/null; then
        redis_status=$(redis-cli ping 2>/dev/null || echo "FAILED")
        echo "   Redis service: $redis_status"
    fi
    
    # Check queue sizes
    active_queue=$(postqueue -p | grep -c "^[A-F0-9]" || echo "0")
    echo "   Active queue size: $active_queue emails"
    
    echo ""
    if [ "$recent_crashes" -eq 0 ] && [ "$recent_processing" -gt 0 ]; then
        print_success "System health looks good!"
    else
        print_warning "System may need attention"
    fi
}

# Main menu loop
while true; do
    show_menu
    read choice
    
    case $choice in
        1) track_sender_receiver ;;
        2) track_from_sender ;;
        3) track_to_receiver ;;
        4) lookup_queue_id ;;
        5) monitor_live ;;
        6) check_redis_status ;;
        7) check_system_health ;;
        8) 
            echo ""
            print_success "Thanks for using SpaCy Email Tracker!"
            exit 0
            ;;
        *)
            print_error "Invalid option. Please select 1-8."
            ;;
    esac
    
    echo ""
    echo -n "Press Enter to continue..."
    read
done
