#!/bin/bash
# run_server.sh - Production server startup script

export UAHP_DATABASE_URL="sqlite:///uahp_v054_registry.db"
export UAHP_RATE_LIMIT="100"
export UAHP_RATE_LIMIT_WINDOW="60"
export UAHP_CORS_ORIGINS="https://yourdomain.com,https://app.yourdomain.com"
export UAHP_REQUIRE_HTTPS="true"

# Initialize database
python -c "from uahp.models import init_db, get_engine; init_db(get_engine())"

# Run migrations
alembic upgrade head

# Start server with uvicorn
exec uvicorn uahp.server:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 4 \
    --ssl-keyfile /path/to/key.pem \
    --ssl-certfile /path/to/cert.pem \
    --log-level info
