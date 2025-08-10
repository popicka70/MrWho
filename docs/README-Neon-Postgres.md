# Neon Postgres Compose Profile

Create a .env file in the repository root and set the connection string used by `docker-compose.postgres.neon.yml`:

NEON_PG_CONNSTR=Host=ep-polished-morning-a2ru6vwg-pooler.eu-central-1.aws.neon.tech;Database=neondb;Username=neondb_owner;Password=REDACTED;Ssl Mode=Require;Channel Binding=Require

Or use the URI format:

NEON_PG_CONNSTR=postgresql://neondb_owner:REDACTED@ep-polished-morning-a2ru6vwg-pooler.eu-central-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require

Then run the profile:

```powershell
docker compose -f "docker-compose.postgres.neon.yml" up --build -d
```

Note: Do not commit secrets. Keep your .env out of version control.
