#!/bin/bash
# SecureAuth MFA — Local Setup Script
set -e

echo ""
echo "╔══════════════════════════════════════╗"
echo "║     SecureAuth MFA — Local Setup     ║"
echo "╚══════════════════════════════════════╝"
echo ""

# # ── 1. Check Python ───────────────────────────────────────────────────────────
# if ! command -v python &>/dev/null; then
#     echo "❌  Python 3 not found. Install it from https://python.org"
#     exit 1
# fi
# PYTHON=$(command -v python)
# echo "✅  Python: $($PYTHON --version)"

# # ── 2. Check MySQL ────────────────────────────────────────────────────────────
# if ! command -v mysql &>/dev/null; then
#     echo ""
#     echo "❌  MySQL client not found."
#     echo "    Install MySQL 8.x then re-run this script."
#     echo "    macOS:  brew install mysql"
#     echo "    Ubuntu: sudo apt install mysql-server"
#     exit 1
# fi
# echo "✅  MySQL client found"

# ── 3. Collect DB credentials ─────────────────────────────────────────────────
echo ""
echo "── MySQL Configuration ─────────────────"
read -p "  MySQL host     [localhost]: " DB_HOST;  DB_HOST=${DB_HOST:-localhost}
read -p "  MySQL port     [3306]:      " DB_PORT;  DB_PORT=${DB_PORT:-3306}
read -p "  MySQL user     [root]:      " DB_USER;  DB_USER=${DB_USER:-root}
read -s -p "  MySQL password: "                    DB_PASSWORD; echo ""
read -p "  Database name  [secureauth_db]: "       DB_NAME; DB_NAME=${DB_NAME:-secureauth_db}

# ── 4. Create the database ────────────────────────────────────────────────────
echo ""
echo "── Creating database ───────────────────"
mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASSWORD" \
    -e "CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4;" 2>/dev/null \
    && echo "✅  Database '$DB_NAME' ready" \
    || { echo "❌  Could not connect to MySQL. Check credentials."; exit 1; }

# ── 5. Write .env ──────────────────────────────────────────────────────────────
cat > .env <<EOF
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_NAME=$DB_NAME
EOF
echo "✅  .env written"

# ── 6. Virtual environment ────────────────────────────────────────────────────
echo ""
echo "── Python environment ──────────────────"
if [ ! -d ".venv" ]; then
    $PYTHON -m venv .venv
    echo "✅  Virtual environment created"
else
    echo "✅  Virtual environment already exists"
fi

source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r backend/requirements.txt
echo "✅  Dependencies installed"

# ── 7. Done ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════╗"
echo "║          Setup complete! 🎉          ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "  Start the server:"
echo "    source .venv/bin/activate"
echo "    python run.py"
echo ""
echo "  Then open:  http://localhost:8000"
echo "  API docs:   http://localhost:8000/docs"
echo ""
