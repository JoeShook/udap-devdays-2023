#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["nuget.config", "."]
COPY ["udap.authserver.devdays.csproj", "."]
RUN dotnet restore "udap.authserver.devdays.csproj"
COPY . .
RUN dotnet build "udap.authserver.devdays.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "udap.authserver.devdays.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "udap.authserver.devdays.dll"]