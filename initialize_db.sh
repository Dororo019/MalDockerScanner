#!/bin/bash

################################################################################
# MalDocker Scanner - Database Initialization Script
# 
# PURPOSE:
#   Sets up PostgreSQL database for the MalDocker Scanner application.
#   Creates database, user, schema, and configures environment variables.
#
# WHAT IT DOES:
#   1. Ensures PostgreSQL service is running
#   2. Creates 'docker_security' database
#   3. Creates 'docker_security_logs' user with secure password
#   4. Initializes all required tables (scan_results, vulnerabilities, etc.)
#   5. Generates and saves secure credentials to .env file
#   6. Tests database connection
#
# WHEN TO USE:
#   - First time setup
#   - After PostgreSQL installation
#   - When you get "password authentication failed" errors
#   - To reset the database (WARNING: deletes all existing data)
#
# USAGE:
#   chmod +x initialize_database.sh
#   ./initialize_database.sh
#
# REQUIREMENTS:
#   - PostgreSQL installed (sudo apt install postgresql)
#   - Root/sudo access
#   - init_database.sql file in the same directory
#
################################################################################

set -e  # Exit immediately if any command fails

# Color codes for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  MalDocker Scanner - Database Initialization        ${BLUE}║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_step() {
    echo -e "${BLUE}►${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

# Display header
print_header

# Check if running with proper permissions
if [ "$EUID" -eq 0 ]; then 
    print_warning "Running as root - this is okay for setup"
fi

################################################################################
# STEP 1: Check PostgreSQL Installation
################################################################################
print_step "Step 1: Checking PostgreSQL installation..."

if ! command -v psql &> /dev/null; then
    print_error "PostgreSQL is not installed"
    echo ""
    echo "Install PostgreSQL with:"
    echo "  Ubuntu/Debian: sudo apt install postgresql postgresql-contrib"
    echo "  CentOS/RHEL:   sudo yum install postgresql postgresql-server"
    echo "  macOS:         brew install postgresql"
    exit 1
fi

print_success "PostgreSQL is installed"
PSQL_VERSION=$(psql --version | head -1)
print_info "Version: $PSQL_VERSION"

################################################################################
# STEP 2: Start PostgreSQL Service
################################################################################
print_step "Step 2: Starting PostgreSQL service..."

if command -v systemctl &> /dev/null; then
    # Linux with systemd
    if sudo systemctl is-active --quiet postgresql; then
        print_success "PostgreSQL is already running"
    else
        sudo systemctl start postgresql
        sudo systemctl enable postgresql
        print_success "PostgreSQL service started and enabled"
    fi
elif command -v brew &> /dev/null; then
    # macOS with Homebrew
    brew services start postgresql 2>/dev/null || true
    print_success "PostgreSQL started (Homebrew)"
else
    print_warning "Cannot detect service manager - ensure PostgreSQL is running"
fi

sleep 2  # Give PostgreSQL time to start

################################################################################
# STEP 3: Generate Secure Password
################################################################################
print_step "Step 3: Generating secure database password..."

# Generate a random 32-character password using OpenSSL
# This ensures the password is cryptographically secure
DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)

print_success "Secure password generated (32 characters)"
print_info "Password will be saved to .env file (never shown in terminal)"

################################################################################
# STEP 4: Check for Existing Database
################################################################################
print_step "Step 4: Checking for existing database..."

if sudo -u postgres psql -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw docker_security; then
    print_warning "Database 'docker_security' already exists"
    echo ""
    read -p "Do you want to DELETE and recreate it? (yes/no): " -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        print_info "Keeping existing database - skipping to password update"
        SKIP_DB_CREATE=true
    else
        print_warning "Dropping existing database and user..."
        sudo -u postgres psql << EOF 2>/dev/null || true
DROP DATABASE IF EXISTS docker_security;
DROP USER IF EXISTS docker_security_logs;
EOF
        print_success "Old database and user removed"
        SKIP_DB_CREATE=false
    fi
else
    print_info "No existing database found - will create new one"
    SKIP_DB_CREATE=false
fi

################################################################################
# STEP 5: Create Database and User
################################################################################
if [ "$SKIP_DB_CREATE" != "true" ]; then
    print_step "Step 5: Creating database and user..."
    
    # Create database, user, and grant permissions
    # This is the core of what fixes your "authentication failed" error
    sudo -u postgres psql << EOF
-- Create the database
CREATE DATABASE docker_security;

-- Create the user with the generated password
CREATE USER docker_security_logs WITH PASSWORD '$DB_PASSWORD';

-- Grant all privileges on the database
GRANT ALL PRIVILEGES ON DATABASE docker_security TO docker_security_logs;

-- Connect to the new database
\c docker_security

-- Grant schema permissions (PostgreSQL 15+ requirement)
GRANT ALL ON SCHEMA public TO docker_security_logs;

-- Grant default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO docker_security_logs;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO docker_security_logs;
EOF
    
    if [ $? -eq 0 ]; then
        print_success "Database 'docker_security' created"
        print_success "User 'docker_security_logs' created with secure password"
        print_success "Permissions granted"
    else
        print_error "Failed to create database and user"
        exit 1
    fi
else
    print_step "Step 5: Skipping database creation (already exists)"
fi

################################################################################
# STEP 6: Initialize Database Schema
################################################################################
print_step "Step 6: Initializing database schema (creating tables)..."

if [ -f "init_database.sql" ]; then
    # Run the SQL schema file to create all tables
    # This creates: scan_results, vulnerability_details, malware_detections, etc.
    sudo -u postgres psql -d docker_security -f init_database.sql > /dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        print_success "Database schema initialized"
        
        # Show what tables were created
        TABLE_COUNT=$(sudo -u postgres psql -d docker_security -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public';")
        print_info "Created $TABLE_COUNT tables"
    else
        print_error "Failed to initialize schema from init_database.sql"
        exit 1
    fi
else
    print_warning "init_database.sql not found - creating basic schema..."
    
    # Fallback: create minimal schema if SQL file is missing
    sudo -u postgres psql -d docker_security << 'EOF'
CREATE TABLE IF NOT EXISTS scan_results (
    scan_id SERIAL PRIMARY KEY,
    image_name VARCHAR(255) NOT NULL,
    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    risk_score DECIMAL(5,2),
    risk_level VARCHAR(20)
);

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO docker_security_logs;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO docker_security_logs;
EOF
    
    print_success "Basic schema created (use init_database.sql for full schema)"
fi

################################################################################
# STEP 7: Configure Environment Variables
################################################################################
print_step "Step 7: Configuring environment variables..."

# Create .env file from template or create new one
if [ -f ".env.template" ]; then
    cp .env.template .env
    print_success "Created .env from template"
else
    print_info "Creating new .env file..."
    
    # Generate Flask secret key
    FLASK_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-40)
    
    # Create complete .env file
    cat > .env << EOF
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=docker_security
DB_USER=docker_security_logs
DB_PASSWORD=${DB_PASSWORD}

# Flask Configuration
FLASK_SECRET_KEY=${FLASK_SECRET}
FLASK_ENV=development
FLASK_DEBUG=True

# Scanner Configuration
TRIVY_TIMEOUT=300
CLAMAV_TIMEOUT=600
FALCO_RUNTIME_DURATION=30

# Deployment
PORT=5000
HOST=0.0.0.0
EOF
    
    print_success "Created new .env file with all variables"
fi

# Update the password in .env file
# This is crucial - your Python app reads DB_PASSWORD from here
sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=$DB_PASSWORD/" .env
print_success "Database password saved to .env file"

# Set secure permissions on .env file
chmod 600 .env
print_info ".env file permissions set to 600 (owner read/write only)"

################################################################################
# STEP 8: Test Database Connection
################################################################################
print_step "Step 8: Testing database connection..."

# Test connection using psql
if PGPASSWORD=$DB_PASSWORD psql -h localhost -U docker_security_logs -d docker_security -c "SELECT 1;" &> /dev/null; then
    print_success "Database connection successful!"
else
    print_error "Database connection failed"
    print_info "Check PostgreSQL logs: sudo tail -f /var/log/postgresql/postgresql-*.log"
    exit 1
fi

# Test with Python if available
if command -v python3 &> /dev/null && [ -f "db_handler.py" ]; then
    print_info "Testing Python database connection..."
    
    if python3 -c "from db_handler import get_db; db = get_db(); print('OK')" 2>/dev/null | grep -q "OK"; then
        print_success "Python database connection works!"
    else
        print_warning "Python connection test failed (install requirements.txt first)"
    fi
fi

################################################################################
# STEP 9: Save Credentials Securely
################################################################################
print_step "Step 9: Saving credentials..."

# Create a credentials file for reference
# This file should NEVER be committed to Git
cat > database_credentials.txt << EOF
MalDocker Scanner - Database Credentials
==========================================

Database Name:  docker_security
Database User:  docker_security_logs
Database Password: $DB_PASSWORD
Host: localhost
Port: 5432

PostgreSQL Connection String:
postgresql://docker_security_logs:$DB_PASSWORD@localhost:5432/docker_security

Python Connection (used in db_handler.py):
  host='localhost'
  port='5432'
  database='docker_security'
  user='docker_security_logs'
  password='$DB_PASSWORD'

⚠️  SECURITY WARNINGS:
  1. Keep this file SECURE and PRIVATE
  2. Do NOT commit to Git (already in .gitignore)
  3. Do NOT share publicly
  4. Password is also in .env file
  5. Both files should have restricted permissions

Created: $(date)
==========================================
EOF

chmod 600 database_credentials.txt
print_success "Credentials saved to database_credentials.txt"

################################################################################
# STEP 10: Display Summary
################################################################################
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}              Setup Complete Successfully!            ${GREEN}║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
echo ""

print_info "What was created:"
echo "  • Database: docker_security"
echo "  • User: docker_security_logs"
echo "  • Password: (saved to .env and database_credentials.txt)"
echo "  • Tables: scan_results, vulnerabilities, and more"
echo ""

print_info "Configuration files:"
echo "  • .env - Environment variables (used by Python app)"
echo "  • database_credentials.txt - Full credentials for reference"
echo ""

print_warning "Security reminders:"
echo "  • .env and database_credentials.txt contain passwords"
echo "  • Both files are in .gitignore (won't be committed)"
echo "  • Keep these files secure and never share them"
echo ""

print_info "Next steps:"
echo ""
echo "  1. Install Python dependencies:"
echo "     ${BLUE}python3 -m venv venv${NC}"
echo "     ${BLUE}source venv/bin/activate${NC}"
echo "     ${BLUE}pip install -r requirements.txt${NC}"
echo ""
echo "  2. Test the database connection:"
echo "     ${BLUE}python3 db_handler.py${NC}"
echo ""
echo "  3. Run your first scan:"
echo "     ${BLUE}python3 scanners/scan_orchestrator.py alpine:latest${NC}"
echo ""
echo "  4. Start the web application:"
echo "     ${BLUE}python3 app.py${NC}"
echo "     ${BLUE}# Then visit: http://localhost:5000${NC}"
echo ""

print_success "Database is ready to use!"
echo ""
