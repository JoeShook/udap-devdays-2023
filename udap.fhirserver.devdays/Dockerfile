#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443


FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["nuget.config", "."]
COPY ["udap.fhirserver.devdays.csproj", "."]
RUN dotnet restore "udap.fhirserver.devdays.csproj"
COPY . .

RUN dotnet build "udap.fhirserver.devdays.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "udap.fhirserver.devdays.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENV ASPNETCORE_URLS=http://*:80;https://*:443
ENTRYPOINT ["dotnet", "udap.fhirserver.devdays.dll"]

FROM base AS devfinal
COPY SureFhirLabs_CA.cer /etc/ssl/certs
RUN update-ca-certificates
WORKDIR /app
COPY --from=publish /app/publish .
ENV ASPNETCORE_URLS=http://*:80;https://*:443
ENTRYPOINT ["dotnet", "udap.fhirserver.devdays.dll"]