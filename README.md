# Proxy Management System

A full-featured Squid proxy manager and portal with both Python (Flask) and Node.js/Express web interfaces, live monitoring, user management, and PAC file generator.

## Features

- **Squid Proxy Integration**: Pre-configured `squid.conf` with authentication, access controls, and SSL bumping support.
- **CLI Management**: `proxy-manager.sh` script to quickly add, remove, and list proxy users, check service status, and inspect logs.
- **REST Backend & Web Portal**:
  - Flask backend (`backend.py`) & Express server (`web/server.js`)
  - User authentication and access code verification
  - PAC (Proxy Auto-Config) file generation
  - Network and CA certificate management
  - Modern web dashboard for monitoring proxy activity

## Prerequisites

- Squid proxy server (`sudo apt install squid apache2-utils`)
- Python 3.10+ and `pip`
- Node.js 18+ and `npm`

## Setup & Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/MuthamiM/proxy.git
   cd proxy
   ```

2. **Configure Environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your desired ports and secret keys
   ```

3. **Backend Setup**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install flask python-dotenv
   ```

4. **Web Frontend Setup**:
   ```bash
   cd web
   npm install
   ```

5. **Running the Services**:
   - Python Backend:
     ```bash
     python3 backend.py
     ```
   - Web Server:
     ```bash
     cd web && node server.js
     ```

## User Management via CLI

```bash
# Add a proxy user
sudo ./proxy-manager.sh add <username> <password>

# Remove a proxy user
sudo ./proxy-manager.sh remove <username>

# List all users
sudo ./proxy-manager.sh list

# Proxy status and logs
sudo ./proxy-manager.sh status
sudo ./proxy-manager.sh logs
```

## License

ISC / MIT
