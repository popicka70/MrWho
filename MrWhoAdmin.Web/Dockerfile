# syntax=docker/dockerfile:1

# NOTE: Build from the solution root so all referenced projects are in context
# Example: docker build -f MrWhoAdmin.Web/Dockerfile .

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy project files for restore (include all ProjectReferences)
COPY MrWhoAdmin.Web/MrWhoAdmin.Web.csproj MrWhoAdmin.Web/MrWhoAdmin.Web.csproj
COPY MrWhoAdmin.ServiceDefaults/MrWhoAdmin.ServiceDefaults.csproj MrWhoAdmin.ServiceDefaults/MrWhoAdmin.ServiceDefaults.csproj
COPY MrWho.Shared/MrWho.Shared.csproj MrWho.Shared/MrWho.Shared.csproj

RUN dotnet restore "MrWhoAdmin.Web/MrWhoAdmin.Web.csproj"

# Copy full source and publish
COPY . .
RUN dotnet publish "MrWhoAdmin.Web/MrWhoAdmin.Web.csproj" -c Release -o /app/publish -p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .

# Environment defaults suitable for containerized prod
ENV ASPNETCORE_FORWARDEDHEADERS_ENABLED=true
ENV DOTNET_RUNNING_IN_CONTAINER=true

# Respect Railway $PORT at runtime
ENTRYPOINT ["/bin/sh","-c","ASPNETCORE_URLS=http://+:${PORT:-8080} dotnet MrWhoAdmin.Web.dll"]
