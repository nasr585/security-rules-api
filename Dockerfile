# Build
FROM mcr.microsoft.com/dotnet/sdk:11.0 AS build
WORKDIR /src

COPY SecurityRules.sln ./
COPY src/SecurityRules.Domain/SecurityRules.Domain.csproj src/SecurityRules.Domain/
COPY src/SecurityRules.Application/SecurityRules.Application.csproj src/SecurityRules.Application/
COPY src/SecurityRules.Infrastructure/SecurityRules.Infrastructure.csproj src/SecurityRules.Infrastructure/
COPY src/SecurityRules.Api/SecurityRules.Api.csproj src/SecurityRules.Api/
RUN dotnet restore src/SecurityRules.Api/SecurityRules.Api.csproj

COPY . .
RUN dotnet publish src/SecurityRules.Api/SecurityRules.Api.csproj -c Release -o /app/publish --no-restore

# Run
FROM mcr.microsoft.com/dotnet/aspnet:11.0 AS runtime
WORKDIR /app

ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080

RUN groupadd -r app && useradd -r -g app app
USER app

COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "SecurityRules.Api.dll"]
