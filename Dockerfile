# The Subact ID control plane image that a release publishes. No key, certificate or API key is
# generated or baked in. Configuration comes from the environment.
# The throwaway quickstart images are built from quickstart/Dockerfile instead.

# Builds on the host platform. The output is portable IL and the runtime base below sets the
# target architecture, so amd64 and arm64 build without emulation.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0@sha256:e70cdb7f80b0348f5cb85f19a8f670fca061f033d57eed12fa003d58b0e06317 AS build
WORKDIR /src

# Assembly version. Empty keeps the default from Directory.Build.props. A release passes its tag.
ARG VERSION=""

# Project files first, so a source change does not invalidate the restore layer.
COPY global.json Directory.Build.props ./
COPY src/SubactId.Core/SubactId.Core.csproj src/SubactId.Core/packages.lock.json src/SubactId.Core/
COPY src/SubactId.Tokens/SubactId.Tokens.csproj src/SubactId.Tokens/packages.lock.json src/SubactId.Tokens/
COPY src/SubactId.Storage.Ef/SubactId.Storage.Ef.csproj src/SubactId.Storage.Ef/packages.lock.json src/SubactId.Storage.Ef/
COPY src/SubactId.Storage.Postgres/SubactId.Storage.Postgres.csproj src/SubactId.Storage.Postgres/packages.lock.json src/SubactId.Storage.Postgres/
COPY src/SubactId.Storage.Sqlite/SubactId.Storage.Sqlite.csproj src/SubactId.Storage.Sqlite/packages.lock.json src/SubactId.Storage.Sqlite/
COPY src/SubactId.Server/SubactId.Server.csproj src/SubactId.Server/packages.lock.json src/SubactId.Server/
RUN dotnet restore --locked-mode src/SubactId.Server/SubactId.Server.csproj

COPY src/ src/
RUN set -eu; \
    if [ -n "$VERSION" ]; then set -- -p:Version="$VERSION"; else set --; fi; \
    dotnet publish src/SubactId.Server/SubactId.Server.csproj -c Release --no-restore "$@" -o /out/server

# Third-party notices travel with the image: every NuGet package in the server's dependency graph,
# with the licence its nuspec declares, and the package's own licence or notice file where it ships one.
RUN set -eu; \
    out=/out/licenses; mkdir -p "$out"; notices="$out/THIRD-PARTY-NOTICES.md"; \
    { \
      echo '# Third-party notices'; \
      echo; \
      echo 'The NuGet packages in the dependency graph of SubactId.Server, as restored for this image, each'; \
      echo 'with the licence it declares. A package that ships its own licence or notice file has it under'; \
      echo 'third-party/<id>-<version>/ next to this file. The .NET runtime is MIT: its licence and notices'; \
      echo 'are /usr/share/dotnet/LICENSE.txt and /usr/share/dotnet/ThirdPartyNotices.txt. The Debian packages'; \
      echo 'of the base image keep theirs under /usr/share/doc/<package>/copyright.'; \
      echo; \
      echo '| Package | Version | Licence |'; \
      echo '|---|---|---|'; \
    } > "$notices"; \
    packages=$(grep -oE '"path": "[^"/]+/[^"/]+"' src/SubactId.Server/obj/project.assets.json | cut -d'"' -f4 | sort -u); \
    [ -n "$packages" ]; \
    for package in $packages; do \
      dir="${NUGET_PACKAGES:-$HOME/.nuget/packages}/$package"; \
      nuspec=$(find "$dir" -maxdepth 1 -name '*.nuspec' | head -n1); \
      [ -n "$nuspec" ]; \
      id=$(sed -nE 's#.*<id>([^<]+)</id>.*#\1#p' "$nuspec" | head -n1); \
      version=$(sed -nE 's#.*<version>([^<]+)</version>.*#\1#p' "$nuspec" | head -n1); \
      [ -n "$id" ]; \
      [ -n "$version" ]; \
      licence=$(sed -nE 's#.*<license type="expression">([^<]+)</license>.*#\1#p' "$nuspec" | head -n1); \
      [ -n "$licence" ] || licence=$(sed -nE 's#.*<license type="file">([^<]+)</license>.*#third-party/'"$id-$version"'/\1#p' "$nuspec" | head -n1); \
      [ -n "$licence" ] || licence=$(sed -nE 's#.*<licenseUrl>([^<]+)</licenseUrl>.*#\1#p' "$nuspec" | head -n1); \
      [ -n "$licence" ] || licence='not declared by the package'; \
      echo "| $id | $version | $licence |" >> "$notices"; \
      for file in "$dir"/LICENSE* "$dir"/License* "$dir"/license* "$dir"/NOTICE* "$dir"/Notice* "$dir"/THIRD-PARTY* "$dir"/ThirdParty*; do \
        [ -f "$file" ] || continue; \
        mkdir -p "$out/third-party/$id-$version"; cp "$file" "$out/third-party/$id-$version/"; \
      done; \
    done

FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:222759b391a1aaf241166672c8f99b2d4ada452e7b5319f3c6e8f265a37b5ad4 AS server
WORKDIR /app
COPY --from=build /out/server ./
# The licences travel with the image: ours (AGPL-3.0-or-later) and those of what it carries.
COPY LICENSE NOTICE /licenses/
COPY --from=build /out/licenses/ /licenses/

# Version and commit set by the release. Used only as labels.
ARG VERSION=""
ARG REVISION=""
LABEL org.opencontainers.image.title="Subact ID" \
      org.opencontainers.image.description="Agent identity and delegation control plane." \
      org.opencontainers.image.source="https://github.com/subactid/subactid" \
      org.opencontainers.image.url="https://subactid.com" \
      org.opencontainers.image.documentation="https://subactid.com/docs" \
      org.opencontainers.image.vendor="Nikola Živković PR Agencija za programerske usluge Novi Sad" \
      org.opencontainers.image.authors="support@subactid.com" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

ENV ASPNETCORE_HTTP_PORTS=5100
USER $APP_UID
EXPOSE 5100
# Subcommands ("migrate", "doctor", "keys", "agent") are passed as arguments. With none, it serves.
ENTRYPOINT ["dotnet", "/app/SubactId.Server.dll"]
