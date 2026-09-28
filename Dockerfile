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
WORKDIR /app
COPY --from=build /app .
COPY models/ models/
RUN mkdir -p /app/data && chown app /app/data   # feedback volume mount point, writable by the non-root user
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_gcServer=0 \
    DOTNET_GCHeapHardLimit=0x10000000
USER app
EXPOSE 8080
ENTRYPOINT ["dotnet", "PhishingAnalyser.Api.dll"]
