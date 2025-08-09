# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080
EXPOSE 8443
ENV ASPNETCORE_URLS=http://+:8080;https://+:8443
ENV ASPNETCORE_Kestrel__Certificates__Default__Path=/https/aspnetapp.pfx

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY MrWho.sln ./
COPY MrWhoAdmin.Web/MrWhoAdmin.Web.csproj MrWhoAdmin.Web/MrWhoAdmin.Web.csproj
COPY MrWhoAdmin.ServiceDefaults/MrWhoAdmin.ServiceDefaults.csproj MrWhoAdmin.ServiceDefaults/MrWhoAdmin.ServiceDefaults.csproj

RUN dotnet restore "MrWhoAdmin.Web/MrWhoAdmin.Web.csproj"

COPY . .
RUN dotnet publish "MrWhoAdmin.Web/MrWhoAdmin.Web.csproj" -c Release -o /app/publish -p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "MrWhoAdmin.Web.dll"]
