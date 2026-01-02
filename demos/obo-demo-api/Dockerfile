# =============================================================================
# OBO Demo API - Dockerfile
# =============================================================================

# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Central Package Management + NuGet configuration
COPY MrWho/Directory.Packages.props ./Directory.Packages.props
COPY MrWho/Directory.Build.props ./Directory.Build.props
COPY MrWho/nuget.config ./nuget.config

# Copy project file first for restore caching
COPY MrWho/demos/obo-demo-api/obo-demo-api.csproj MrWho/demos/obo-demo-api/
RUN dotnet restore MrWho/demos/obo-demo-api/obo-demo-api.csproj

# Copy source and publish
COPY MrWho/demos/obo-demo-api/ MrWho/demos/obo-demo-api/
WORKDIR /src/MrWho/demos/obo-demo-api
RUN dotnet publish -c Release -o /app/publish --no-restore

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app

# Copy published app
COPY --from=build /app/publish .

# Add curl for health checks and ca-certificates for SSL
RUN apt-get update && apt-get install -y curl ca-certificates && rm -rf /var/lib/apt/lists/*

# Expose ports (HTTPS and HTTP)
EXPOSE 7200 7199

# Run application
ENTRYPOINT ["dotnet", "obo-demo-api.dll"]
