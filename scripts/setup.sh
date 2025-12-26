#!/bin/bash
# ISSEC Toolset - Automated Setup Script
# Usage: ./scripts/setup.sh

set -e

echo "=================================="
echo "ISSEC Toolset - Setup Script"
echo "=================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running from project root
if [ ! -f "run.py" ]; then
    echo -e "${RED}Error: Please run this script from the project root directory${NC}"
    echo "Usage: ./scripts/setup.sh"
    exit 1
fi

# Check Python
echo -e "\n${YELLOW}[1/6] Checking Python...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 is not installed. Please install Python 3.8+${NC}"
    exit 1
fi
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"

# Check PostgreSQL
echo -e "\n${YELLOW}[2/6] Checking PostgreSQL...${NC}"
if ! command -v psql &> /dev/null; then
    echo -e "${RED}PostgreSQL client not found. Please install PostgreSQL${NC}"
    echo "  Ubuntu/Debian: sudo apt install postgresql postgresql-contrib"
    echo "  macOS: brew install postgresql"
    exit 1
fi
echo -e "${GREEN}✓ PostgreSQL client found${NC}"

# Create virtual environment
echo -e "\n${YELLOW}[3/6] Setting up virtual environment...${NC}"
if [ -d ".venv" ]; then
    echo "Virtual environment already exists"
else
    python3 -m venv .venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
fi

# Activate and install dependencies
echo -e "\n${YELLOW}[4/6] Installing dependencies...${NC}"
source .venv/bin/activate
pip install --upgrade pip > /dev/null
pip install -r requirements.txt
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Check/Create .env
echo -e "\n${YELLOW}[5/6] Checking environment configuration...${NC}"
if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${YELLOW}⚠ Created .env from .env.example${NC}"
        echo -e "${YELLOW}  IMPORTANT: Edit .env with your database credentials${NC}"
    else
        echo -e "${RED}No .env.example found${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}✓ .env file exists${NC}"
fi

# Database setup
echo -e "\n${YELLOW}[6/6] Database setup...${NC}"
echo "Do you want to initialize the database? (y/n)"
read -r INIT_DB
if [ "$INIT_DB" = "y" ]; then
    echo "Creating database tables..."
    python scripts/create_tables.py
    echo -e "${GREEN}✓ Database initialized${NC}"
fi

echo ""
echo "=================================="
echo -e "${GREEN}Setup complete!${NC}"
echo "=================================="
echo ""
echo "To start the application:"
echo "  1. Activate virtualenv: source .venv/bin/activate"
echo "  2. Edit .env with your database credentials"
echo "  3. Run: flask run"
echo ""
echo "Default login: admin@issec.com / admin123"
echo ""
