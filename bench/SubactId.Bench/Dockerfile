# The sizing rig's load generator. Build from the repository root.

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0@sha256:e70cdb7f80b0348f5cb85f19a8f670fca061f033d57eed12fa003d58b0e06317 AS build
WORKDIR /src

# Optional CA for networks with a TLS-intercepting proxy: `--secret id=build_ca,src=<pem>`.
RUN --mount=type=secret,id=build_ca,target=/tmp/build-ca.crt \
    set -eu; \
    if [ -s /tmp/build-ca.crt ]; then \
      cp /tmp/build-ca.crt /usr/local/share/ca-certificates/build-proxy.crt; \
      update-ca-certificates; \
    fi

COPY global.json Directory.Build.props ./
COPY bench/Directory.Build.props bench/
COPY bench/SubactId.Bench/SubactId.Bench.csproj bench/SubactId.Bench/packages.lock.json bench/SubactId.Bench/
RUN --mount=type=secret,id=build_ca,target=/tmp/build-ca.crt \
    dotnet restore --locked-mode bench/SubactId.Bench/SubactId.Bench.csproj

COPY bench/SubactId.Bench/ bench/SubactId.Bench/
RUN dotnet publish bench/SubactId.Bench/SubactId.Bench.csproj -c Release --no-restore -o /out/bench

FROM mcr.microsoft.com/dotnet/runtime:10.0@sha256:b89586dc17781f25531909993658aa8161205ae38b8cec8847df4a8221a403d5
WORKDIR /app
COPY --from=build /out/bench ./
# Results are copied out with docker cp after the run (bench.sh), so nothing here needs root.
USER $APP_UID
ENTRYPOINT ["dotnet", "/app/SubactId.Bench.dll"]
