#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:5.0-buster-slim AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443
RUN apt update
RUN apt install -y libgdiplus


FROM mcr.microsoft.com/dotnet/sdk:5.0-buster-slim AS build
WORKDIR /src
COPY ["EdwardHsu.Lab.TOTP/EdwardHsu.Lab.TOTP.csproj", "EdwardHsu.Lab.TOTP/"]
RUN dotnet restore "EdwardHsu.Lab.TOTP/EdwardHsu.Lab.TOTP.csproj"
COPY . .
WORKDIR "/src/EdwardHsu.Lab.TOTP"
RUN dotnet build "EdwardHsu.Lab.TOTP.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "EdwardHsu.Lab.TOTP.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "EdwardHsu.Lab.TOTP.dll"]