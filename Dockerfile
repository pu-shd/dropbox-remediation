# Test container for the Dropbox watchdog Intune remediation package.
#
# The shipped scripts target Windows PowerShell 5.1 on Windows 11, which cannot run
# here. Instead the suite mocks the Windows-only surface (Task Scheduler, WMI, the
# registry, the event log) behind wrapper functions and exercises the real logic on
# PowerShell 7. Every unmocked Windows shim throws, so a missing mock fails the test
# rather than quietly passing.
#
# Built on ubuntu:22.04 rather than the official PowerShell image because that image
# is published for amd64 only; installing pwsh from the release tarball keeps the
# suite native on Apple Silicon as well as on amd64 CI runners.
FROM ubuntu:22.04

ARG PWSH_VERSION=7.4.6
ARG PESTER_VERSION=5.6.1
ARG PSSA_VERSION=1.22.0

ENV DEBIAN_FRONTEND=noninteractive \
    POWERSHELL_TELEMETRY_OPTOUT=1 \
    POWERSHELL_UPDATECHECK=Off \
    DOTNET_CLI_TELEMETRY_OPTOUT=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl zsh gzip coreutils jq libicu70 libssl3 locales \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) pwsh_arch=x64 ;; \
      arm64) pwsh_arch=arm64 ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/pwsh.tar.gz \
      "https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VERSION}/powershell-${PWSH_VERSION}-linux-${pwsh_arch}.tar.gz"; \
    mkdir -p /opt/microsoft/powershell/7; \
    tar zxf /tmp/pwsh.tar.gz -C /opt/microsoft/powershell/7; \
    chmod +x /opt/microsoft/powershell/7/pwsh; \
    ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh; \
    rm /tmp/pwsh.tar.gz; \
    pwsh --version

# Install-PSResource ships with PowerShell 7.4 and needs no NuGet provider bootstrap,
# which would otherwise block on an interactive prompt in a container build.
RUN pwsh -NoLogo -NoProfile -NonInteractive -Command \
      "\$ErrorActionPreference='Stop'; \
       Install-PSResource -Name Pester -Version '${PESTER_VERSION}' -Repository PSGallery -TrustRepository -Scope AllUsers -Reinstall; \
       Install-PSResource -Name PSScriptAnalyzer -Version '${PSSA_VERSION}' -Repository PSGallery -TrustRepository -Scope AllUsers -Reinstall; \
       if (-not (Get-Module -ListAvailable Pester | Where-Object Version -eq '${PESTER_VERSION}')) { throw 'Pester ${PESTER_VERSION} did not install' }; \
       if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) { throw 'PSScriptAnalyzer did not install' }"

WORKDIR /work
COPY . /work
RUN chmod +x /work/scripts/*.sh /work/scripts/lib/*.sh

ENTRYPOINT ["pwsh", "-NoLogo", "-NoProfile", "-File", "/work/tests/Invoke-Tests.ps1"]
