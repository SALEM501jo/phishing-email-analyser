# ---- build ----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY Directory.Build.props ./
COPY src/PhishingAnalyser.Core/PhishingAnalyser.Core.csproj src/PhishingAnalyser.Core/
COPY src/PhishingAnalyser.Api/PhishingAnalyser.Api.csproj src/PhishingAnalyser.Api/
RUN dotnet restore src/PhishingAnalyser.Api/PhishingAnalyser.Api.csproj
COPY src/ src/
RUN dotnet publish src/PhishingAnalyser.Api/PhishingAnalyser.Api.csproj -c Release -o /app --no-restore

# ---- runtime ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0
# Apply pending Debian security updates: the base image can lag behind a fix (the Trivy gate caught libpcre2 this way).
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app .
# Model binaries come from a GitHub Release (python scripts/models.py fetch); CI fetches them before this build.
COPY models/ models/
RUN mkdir -p /app/data && chown app /app/data   # feedback volume mount point, writable by the non-root user
# 8080 = the API (behind the reverse proxy); 9464 = Prometheus metrics (internal only)
ENV ASPNETCORE_HTTP_PORTS="8080;9464" \
    DOTNET_gcServer=0 \
    DOTNET_GCHeapHardLimit=0x14000000
USER app
EXPOSE 8080 9464
# The runtime image has no curl, so the API binary probes its own /health (no web host is started for this).
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD ["dotnet", "PhishingAnalyser.Api.dll", "--healthcheck"]
ENTRYPOINT ["dotnet", "PhishingAnalyser.Api.dll"]
