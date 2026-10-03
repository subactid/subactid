# The quickstart images: control plane, sample tool server, demo agent and portal, all built
# from one restore.
#
# Never push these images. The bootstrap stage bakes in a throwaway signing key, admin API key
# and certificate authority. The published image is built from the root Dockerfile instead.
#
# The build context is the repository root:
#
#   docker build -f quickstart/Dockerfile --target demo-agent ..
#
# compose.yaml does this for each service.

FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:e70cdb7f80b0348f5cb85f19a8f670fca061f033d57eed12fa003d58b0e06317 AS build
WORKDIR /src

# Project files first, so a source change does not invalidate the restore layer.
COPY global.json Directory.Build.props ./
COPY src/SubactId.Core/SubactId.Core.csproj src/SubactId.Core/packages.lock.json src/SubactId.Core/
COPY src/SubactId.Tokens/SubactId.Tokens.csproj src/SubactId.Tokens/packages.lock.json src/SubactId.Tokens/
COPY src/SubactId.Storage.Ef/SubactId.Storage.Ef.csproj src/SubactId.Storage.Ef/packages.lock.json src/SubactId.Storage.Ef/
COPY src/SubactId.Storage.Postgres/SubactId.Storage.Postgres.csproj src/SubactId.Storage.Postgres/packages.lock.json src/SubactId.Storage.Postgres/
COPY src/SubactId.Storage.Sqlite/SubactId.Storage.Sqlite.csproj src/SubactId.Storage.Sqlite/packages.lock.json src/SubactId.Storage.Sqlite/
COPY src/SubactId.Server/SubactId.Server.csproj src/SubactId.Server/packages.lock.json src/SubactId.Server/
COPY samples/Directory.Build.props samples/
COPY samples/SubactId.Sample.ToolServer/SubactId.Sample.ToolServer.csproj samples/SubactId.Sample.ToolServer/packages.lock.json samples/SubactId.Sample.ToolServer/
COPY samples/SubactId.Sample.Agent/SubactId.Sample.Agent.csproj samples/SubactId.Sample.Agent/packages.lock.json samples/SubactId.Sample.Agent/
COPY samples/SubactId.Sample.Portal/SubactId.Sample.Portal.csproj samples/SubactId.Sample.Portal/packages.lock.json samples/SubactId.Sample.Portal/
RUN dotnet restore --locked-mode src/SubactId.Server/SubactId.Server.csproj \
    && dotnet restore --locked-mode samples/SubactId.Sample.ToolServer/SubactId.Sample.ToolServer.csproj \
    && dotnet restore --locked-mode samples/SubactId.Sample.Agent/SubactId.Sample.Agent.csproj \
    && dotnet restore --locked-mode samples/SubactId.Sample.Portal/SubactId.Sample.Portal.csproj

COPY src/ src/
COPY samples/ samples/
RUN dotnet publish src/SubactId.Server/SubactId.Server.csproj -c Release --no-restore -o /out/server \
    && dotnet publish samples/SubactId.Sample.ToolServer/SubactId.Sample.ToolServer.csproj -c Release --no-restore -o /out/tool-server \
    && dotnet publish samples/SubactId.Sample.Agent/SubactId.Sample.Agent.csproj -c Release --no-restore -o /out/agent \
    && dotnet publish samples/SubactId.Sample.Portal/SubactId.Sample.Portal.csproj -c Release --no-restore -o /out/portal

# The control plane, without demo credentials. Mirrors the published image.
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:222759b391a1aaf241166672c8f99b2d4ada452e7b5319f3c6e8f265a37b5ad4 AS control-plane
WORKDIR /app
COPY --from=build /out/server ./
ENV ASPNETCORE_HTTP_PORTS=5100
USER $APP_UID
EXPOSE 5100
ENTRYPOINT ["dotnet", "/app/SubactId.Server.dll"]

# The sample tool server.
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:222759b391a1aaf241166672c8f99b2d4ada452e7b5319f3c6e8f265a37b5ad4 AS tool-server
WORKDIR /app
COPY --from=build /out/tool-server ./
USER $APP_UID
EXPOSE 8080
ENTRYPOINT ["dotnet", "/app/SubactId.Sample.ToolServer.dll"]

# Generates the throwaway secrets the demo needs at build time: the signing key, the admin API
# key, and a CA for the agents' https JWKS endpoints. Never committed.
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:e70cdb7f80b0348f5cb85f19a8f670fca061f033d57eed12fa003d58b0e06317 AS quickstart-bootstrap
WORKDIR /bootstrap
RUN set -eu; \
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out signing.pem; \
    openssl rand -hex 32 | tr -d '\n' > admin-key; \
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
        -keyout ca.key -out ca.crt -subj "/CN=subactid-quickstart-ca"; \
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout agent.key -out agent.csr -subj "/CN=demo-agent"; \
    printf "subjectAltName=DNS:demo-agent,DNS:portal-agent\nextendedKeyUsage=serverAuth\n" > agent.ext; \
    openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
        -extfile agent.ext -out agent.crt; \
    printf '{"SubactId":{"Admin":{"ApiKey":"%s"},"Signing":{"ActiveKid":"quickstart","Keys":[{"Kid":"quickstart","Path":"/etc/subactid/signing.pem"}]}}}' "$(cat admin-key)" > appsettings.json

# The control plane with demo credentials and the demo CA, since agent JWKS must be fetched over https.
FROM control-plane AS quickstart-server
USER root
COPY --from=quickstart-bootstrap /bootstrap/ca.crt /usr/local/share/ca-certificates/subactid-quickstart-ca.crt
COPY --from=quickstart-bootstrap /bootstrap/signing.pem /bootstrap/admin-key /etc/subactid/
COPY --from=quickstart-bootstrap /bootstrap/appsettings.json /app/appsettings.json
RUN update-ca-certificates \
    && chown "$APP_UID" /etc/subactid/signing.pem /app/appsettings.json \
    && chmod 400 /etc/subactid/signing.pem /app/appsettings.json \
    && chmod 444 /etc/subactid/admin-key
USER $APP_UID

# The demo agent. It gets the admin API key only to register itself and read the ledger for the demo.
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:222759b391a1aaf241166672c8f99b2d4ada452e7b5319f3c6e8f265a37b5ad4 AS demo-agent
WORKDIR /app
COPY --from=build /out/agent ./
COPY --from=quickstart-bootstrap /bootstrap/agent.key /bootstrap/agent.crt /bootstrap/admin-key /etc/subactid-quickstart/
# Serves its JWKS over https only.
ENV ASPNETCORE_HTTP_PORTS="" \
    ASPNETCORE_HTTPS_PORTS=8443 \
    Kestrel__Certificates__Default__Path=/etc/subactid-quickstart/agent.crt \
    Kestrel__Certificates__Default__KeyPath=/etc/subactid-quickstart/agent.key
RUN chown "$APP_UID" /etc/subactid-quickstart/agent.key \
    && chmod 400 /etc/subactid-quickstart/agent.key \
    && chmod 444 /etc/subactid-quickstart/agent.crt /etc/subactid-quickstart/admin-key \
    && mkdir -p /var/lib/demo-agent \
    && chown "$APP_UID" /var/lib/demo-agent
USER $APP_UID
EXPOSE 8443
ENTRYPOINT ["dotnet", "/app/SubactId.Sample.Agent.dll"]

# The same agent, run as the service the portal drives. It gets the admin key to register itself
# and to use the kill switch for the page. A real agent would not hold an admin key.
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:222759b391a1aaf241166672c8f99b2d4ada452e7b5319f3c6e8f265a37b5ad4 AS portal-agent
WORKDIR /app
COPY --from=build /out/agent ./
COPY --from=quickstart-bootstrap /bootstrap/agent.key /bootstrap/agent.crt /bootstrap/admin-key /etc/subactid-quickstart/
# Service API on http for the portal, JWKS on https for the control plane.
ENV ASPNETCORE_HTTP_PORTS=8100 \
    ASPNETCORE_HTTPS_PORTS=8443 \
    Kestrel__Certificates__Default__Path=/etc/subactid-quickstart/agent.crt \
    Kestrel__Certificates__Default__KeyPath=/etc/subactid-quickstart/agent.key
RUN chown "$APP_UID" /etc/subactid-quickstart/agent.key \
    && chmod 400 /etc/subactid-quickstart/agent.key \
    && chmod 444 /etc/subactid-quickstart/agent.crt /etc/subactid-quickstart/admin-key \
    && mkdir -p /var/lib/portal-agent \
    && chown "$APP_UID" /var/lib/portal-agent
USER $APP_UID
EXPOSE 8100 8443
ENTRYPOINT ["dotnet", "/app/SubactId.Sample.Agent.dll", "serve"]

# The portal the human signs in to. The only part of the demo that holds the human's token. It
# reads the ledger with the admin key, which a real application would not have.
FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:222759b391a1aaf241166672c8f99b2d4ada452e7b5319f3c6e8f265a37b5ad4 AS portal
WORKDIR /app
COPY --from=build /out/portal ./
COPY --from=quickstart-bootstrap /bootstrap/admin-key /etc/subactid-quickstart/
ENV ASPNETCORE_HTTP_PORTS=8090
RUN chmod 444 /etc/subactid-quickstart/admin-key
USER $APP_UID
EXPOSE 8090
ENTRYPOINT ["dotnet", "/app/SubactId.Sample.Portal.dll"]
