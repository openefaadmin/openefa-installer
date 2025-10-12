#!/bin/bash
#
# compile_email_filter.sh - SpaCy Email Filter Deployment Script
# Compiles, validates, and deploys the email filter with safety checks
#
# Usage: ./compile_email_filter.sh [options]
# Options:
#   -t, --test          Test mode - validate syntax only
#   -b, --backup        Force create backup before deployment
#   -r, --restart       Restart postfix after deployment
#   -v, --verbose       Verbose output
#   -h, --help          Show this help
#

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
FILTER_SOURCE="${SCRIPT_DIR}/email_filter.py"
FILTER_TARGET="/opt/spacyserver/email_filter.py"
BACKUP_DIR="/opt/spacyserver/backups"
VENV_PATH="/opt/spacyserver/venv"
POSTFIX_MAIN_CF="/etc/postfix/main.cf"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
TEST_MODE=false
FORCE_BACKUP=false
RESTART_POSTFIX=false
VERBOSE=false

# =============================================================================
# FUNCTIONS
# =============================================================================

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] DEBUG:${NC} $1"
    fi
}

show_help() {
    cat << EOF
SpaCy Email Filter Compilation and Deployment Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -t, --test          Test mode - validate syntax and imports only
    -b, --backup        Force create backup before deployment
    -r, --restart       Restart postfix after deployment
    -v, --verbose       Enable verbose output
    -h, --help          Show this help message

EXAMPLES:
    $0                  # Standard deployment
    $0 -t               # Test syntax only
    $0 -b -r            # Backup and restart postfix
    $0 -v -t            # Verbose test mode

PATHS:
    Source:      ${FILTER_SOURCE}
    Target:      ${FILTER_TARGET}
    Backup Dir:  ${BACKUP_DIR}
    Virtual Env: ${VENV_PATH}

EOF
}

check_prerequisites() {
    verbose "Checking prerequisites..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (for file permissions)"
        exit 1
    fi
    
    # Check if source file exists
    if [[ ! -f "$FILTER_SOURCE" ]]; then
        error "Source file not found: $FILTER_SOURCE"
        exit 1
    fi
    
    # Check if virtual environment exists
    if [[ ! -d "$VENV_PATH" ]]; then
        warn "Virtual environment not found at $VENV_PATH"
        warn "Python modules may not import correctly"
    fi
    
    # Check target directory
    if [[ ! -d "$(dirname "$FILTER_TARGET")" ]]; then
        error "Target directory not found: $(dirname "$FILTER_TARGET")"
        exit 1
    fi
    
    verbose "Prerequisites check passed"
}

create_backup() {
    if [[ -f "$FILTER_TARGET" ]] && [[ "$FORCE_BACKUP" == "true" || "$TEST_MODE" == "false" ]]; then
        # Create backup directory if it doesn't exist
        mkdir -p "$BACKUP_DIR"
        
        # Create timestamped backup
        local backup_file="$BACKUP_DIR/email_filter_$(date +%Y%m%d_%H%M%S).py"
        cp "$FILTER_TARGET" "$backup_file"
        log "Backup created: $backup_file"
        
        # Keep only last 10 backups
        cd "$BACKUP_DIR"
        ls -t email_filter_*.py | tail -n +11 | xargs rm -f 2>/dev/null || true
        verbose "Old backups cleaned up"
    fi
}

validate_syntax() {
    log "Validating Python syntax..."
    
    # Use the virtual environment Python if available
    local python_cmd="python3"
    if [[ -f "$VENV_PATH/bin/python3" ]]; then
        python_cmd="$VENV_PATH/bin/python3"
        verbose "Using virtual environment Python: $python_cmd"
    fi
    
    # Check syntax
    if ! $python_cmd -m py_compile "$FILTER_SOURCE"; then
        error "Python syntax validation failed!"
        return 1
    fi
    
    # Check for basic imports
    verbose "Checking basic imports..."
    if ! $python_cmd -c "
import sys
sys.path.insert(0, '/opt/spacyserver/modules')
try:
    import ast
    with open('$FILTER_SOURCE', 'r') as f:
        ast.parse(f.read())
    print('✓ AST parsing successful')
except SyntaxError as e:
    print(f'✗ Syntax error: {e}')
    sys.exit(1)
except Exception as e:
    print(f'⚠ Warning: {e}')
"; then
        error "Import validation failed!"
        return 1
    fi
    
    log "✅ Syntax validation passed"
    return 0
}

validate_configuration() {
    verbose "Validating email filter configuration..."
    
    # Check for required configuration sections
    local required_patterns=(
        "class EmailFilterConfig"
        "CONFIG = EmailFilterConfig"
        "def should_block_email"
        "def main()"
        "MODULE_MANAGER"
    )
    
    for pattern in "${required_patterns[@]}"; do
        if ! grep -q "$pattern" "$FILTER_SOURCE"; then
            error "Required pattern not found: $pattern"
            return 1
        fi
    done
    
    # Check for enhanced blocking logic
    if grep -q "X-Thread-Spam-Repetition" "$FILTER_SOURCE"; then
        verbose "✓ Enhanced thread spam detection found"
    else
        warn "Enhanced thread spam detection not found"
    fi
    
    if grep -q "critical_indicators" "$FILTER_SOURCE"; then
        verbose "✓ Critical indicators logic found"
    else
        warn "Critical indicators logic not found"
    fi
    
    log "✅ Configuration validation passed"
    return 0
}

test_email_filter() {
    log "Testing email filter functionality..."
    
    local python_cmd="python3"
    if [[ -f "$VENV_PATH/bin/python3" ]]; then
        python_cmd="$VENV_PATH/bin/python3"
    fi
    
    # Test import and basic initialization
    if ! $python_cmd -c "
import sys
sys.path.insert(0, '/opt/spacyserver/modules')
sys.path.insert(0, '$(dirname "$FILTER_SOURCE")')

try:
    # Import main components using exec approach
    import importlib.util
    spec = importlib.util.spec_from_file_location('email_filter_test', '$FILTER_SOURCE')
    email_filter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(email_filter)
    
    # Test basic configuration
    if hasattr(email_filter, 'EmailFilterConfig'):
        config = email_filter.EmailFilterConfig()
        print(f'✓ Configuration loaded: {len(config.config)} sections')
    else:
        print('⚠ EmailFilterConfig class not found, checking alternatives...')
        # Look for CONFIG global variable
        if hasattr(email_filter, 'CONFIG'):
            print('✓ CONFIG global variable found')
        else:
            raise AttributeError('Neither EmailFilterConfig class nor CONFIG variable found')
    
    # Test module manager
    if hasattr(email_filter, 'ModuleManager'):
        module_manager = email_filter.ModuleManager()
        available_modules = sum(module_manager.available.values())
        total_modules = len(module_manager.available)
        print(f'✓ Module manager: {available_modules}/{total_modules} modules available')
    else:
        print('⚠ ModuleManager class not found')
    
    # Test performance monitor
    if hasattr(email_filter, 'PerformanceMonitor'):
        monitor = email_filter.PerformanceMonitor()
        print(f'✓ Performance monitor initialized')
    else:
        print('⚠ PerformanceMonitor class not found')
    
    # Test enhanced blocking function
    if hasattr(email_filter, 'should_block_email'):
        print('✓ Enhanced blocking function found')
    else:
        print('⚠ should_block_email function not found')
    
    # Test thread spam detection
    if hasattr(email_filter, 'enhanced_thread_spam_detection'):
        print('✓ Enhanced thread spam detection found')
    else:
        print('⚠ enhanced_thread_spam_detection function not found')
    
    print('✅ Basic functionality test passed')
    
except Exception as e:
    print(f'✗ Functionality test failed: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"; then
        error "Functionality test failed!"
        return 1
    fi
    
    log "✅ Functionality test passed"
    return 0
}

deploy_filter() {
    if [[ "$TEST_MODE" == "true" ]]; then
        log "Test mode - skipping actual deployment"
        return 0
    fi
    
    log "Deploying email filter..."
    
    # Check if source and target are the same file
    if [[ "$(realpath "$FILTER_SOURCE")" == "$(realpath "$FILTER_TARGET")" ]]; then
        log "Source and target are the same file - updating in place"
        # Just update permissions since file is already in place
        chown root:root "$FILTER_TARGET"
        chmod 755 "$FILTER_TARGET"
        verbose "File permissions updated: $(ls -la "$FILTER_TARGET")"
    else
        # Copy file with proper permissions
        cp "$FILTER_SOURCE" "$FILTER_TARGET"
        chown root:root "$FILTER_TARGET"
        chmod 755 "$FILTER_TARGET"
        verbose "File copied and permissions set: $(ls -la "$FILTER_TARGET")"
    fi
    
    # Verify the deployed file
    if [[ ! -f "$FILTER_TARGET" ]]; then
        error "Deployment failed - target file not found"
        return 1
    fi
    
    # Quick syntax check on deployed file
    local python_cmd="python3"
    if [[ -f "$VENV_PATH/bin/python3" ]]; then
        python_cmd="$VENV_PATH/bin/python3"
    fi
    
    if ! $python_cmd -m py_compile "$FILTER_TARGET"; then
        error "Deployed file failed syntax check!"
        return 1
    fi
    
    log "✅ Email filter deployed successfully"
    return 0
}

check_postfix_integration() {
    verbose "Checking Postfix integration..."
    
    if [[ -f "$POSTFIX_MAIN_CF" ]]; then
        if grep -q "spacy" "$POSTFIX_MAIN_CF"; then
            verbose "✓ SpaCy configuration found in Postfix"
        else
            warn "SpaCy configuration not found in Postfix main.cf"
        fi
        
        # Check master.cf for the actual email filter path
        local master_cf="/etc/postfix/master.cf"
        if [[ -f "$master_cf" ]]; then
            # Look for argv= line that contains our email filter path
            if grep -A 5 "spacyfilter" "$master_cf" | grep -q "argv=$FILTER_TARGET"; then
                verbose "✓ Email filter path found in Postfix master.cf"
            elif grep -A 5 "spacyfilter" "$master_cf" | grep -q "argv=.*email_filter.py"; then
                local found_path=$(grep -A 5 "spacyfilter" "$master_cf" | grep "argv=" | sed 's/.*argv=\([^ ]*\).*/\1/')
                verbose "✓ Email filter found at: $found_path"
                if [[ "$found_path" != "$FILTER_TARGET" ]]; then
                    warn "Path mismatch: Postfix uses $found_path, script expects $FILTER_TARGET"
                fi
            else
                warn "Email filter path not found in Postfix master.cf"
            fi
            
            # Check spacyfilter service configuration
            if grep -q "spacyfilter.*pipe" "$master_cf"; then
                verbose "✓ SpaCy filter service configured in master.cf"
                # Show service details if verbose
                if [[ "$VERBOSE" == "true" ]]; then
                    echo "  SpaCy filter configuration:"
                    grep -A 4 "spacyfilter.*pipe" "$master_cf" | sed 's/^/    /'
                fi
            else
                warn "SpaCy filter service not found in master.cf"
            fi
        else
            warn "Postfix master.cf not found at $master_cf"
        fi
    else
        warn "Postfix main.cf not found at $POSTFIX_MAIN_CF"
    fi
}

restart_postfix() {
    if [[ "$RESTART_POSTFIX" == "true" && "$TEST_MODE" == "false" ]]; then
        log "Restarting Postfix..."
        
        # Check Postfix configuration first
        if ! postfix check; then
            error "Postfix configuration check failed!"
            return 1
        fi
        
        # Restart Postfix
        if systemctl restart postfix; then
            log "✅ Postfix restarted successfully"
            
            # Check status
            if systemctl is-active --quiet postfix; then
                verbose "✓ Postfix is running"
            else
                error "Postfix failed to start properly"
                return 1
            fi
        else
            error "Failed to restart Postfix"
            return 1
        fi
    fi
}

show_summary() {
    log "Deployment Summary:"
    echo "  Source:      $FILTER_SOURCE"
    echo "  Target:      $FILTER_TARGET"
    if [[ "$TEST_MODE" == "true" ]]; then
        echo "  Mode:        TEST ONLY"
    else
        echo "  Mode:        DEPLOYED"
        echo "  Backup:      $(ls -t "$BACKUP_DIR"/email_filter_*.py 2>/dev/null | head -1 || echo "None")"
    fi
    echo "  Timestamp:   $(date)"
    
    # Show current thresholds
    if [[ -f "$FILTER_TARGET" || "$TEST_MODE" == "true" ]]; then
        echo ""
        echo "Current Configuration:"
        echo "  SPACY_SPAM_THRESHOLD: ${SPACY_SPAM_THRESHOLD:-6.0}"
        echo "  SPACY_THREAD_TRUST_THRESHOLD: ${SPACY_THREAD_TRUST_THRESHOLD:--3.0}"
        echo "  SPACY_CRITICAL_INDICATORS_THRESHOLD: ${SPACY_CRITICAL_INDICATORS_THRESHOLD:-3}"
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--test)
                TEST_MODE=true
                shift
                ;;
            -b|--backup)
                FORCE_BACKUP=true
                shift
                ;;
            -r|--restart)
                RESTART_POSTFIX=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    log "Starting SpaCy Email Filter compilation..."
    
    # Execute deployment steps
    check_prerequisites
    create_backup
    validate_syntax
    validate_configuration
    test_email_filter
    deploy_filter
    check_postfix_integration
    restart_postfix
    show_summary
    
    if [[ "$TEST_MODE" == "true" ]]; then
        log "✅ Test completed successfully - ready for deployment"
    else
        log "✅ Email filter deployed successfully"
    fi
}

# Execute main function
main "$@"
