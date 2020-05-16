FROM mcr.microsoft.com/dotnet/core/aspnet:3.1
WORKDIR /app

COPY . /app



POINT /obs-conf/launch.sh

ENTRYPOINT ["dotnet", "CertificateAuthority.dll", "--environment=Development"]
