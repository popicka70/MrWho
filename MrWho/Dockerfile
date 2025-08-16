# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# Copy solution and project files first for better caching
COPY MrWho.sln ./
COPY MrWho/MrWho.csproj MrWho/MrWho.csproj
COPY MrWho.Shared/MrWho.Shared.csproj MrWho.Shared/MrWho.Shared.csproj
COPY MrWhoAdmin.ServiceDefaults/MrWhoAdmin.ServiceDefaults.csproj MrWhoAdmin.ServiceDefaults/MrWhoAdmin.ServiceDefaults.csproj

# Restore dependencies for the app and migration projects that were staged
RUN dotnet restore "MrWho/MrWho.csproj"

# Copy the rest of the source and publish
COPY . .
RUN dotnet publish "MrWho/MrWho.csproj" -c Release -o /app/publish -p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["/bin/sh","-c","ASPNETCORE_URLS=http://+:${PORT:-8080} dotnet MrWho.dll"]
