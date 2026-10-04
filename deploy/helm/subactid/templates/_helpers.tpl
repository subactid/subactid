{{/*
Names. A release name that already contains the chart name is used as is, so
`helm install subactid subactid/subactid` produces `subactid`, not `subactid-subactid`.
*/}}
{{- define "subactid.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "subactid.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "subactid.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "subactid.labels" -}}
helm.sh/chart: {{ include "subactid.chart" . }}
{{ include "subactid.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: subactid
{{- end }}

{{- define "subactid.selectorLabels" -}}
app.kubernetes.io/name: {{ include "subactid.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Labels for the pods that are not the server: the migrate Job's and the test pod's. They keep the
release's instance label, so they list with the release, but carry a name of their own, so the
Service, the PodDisruptionBudget and the NetworkPolicy, which select by name and instance, never
pick them up: neither pod serves requests, and the policy's egress rules would cut the test pod
off from the server. Both take a dict with "context" (the root) and "component".
*/}}
{{- define "subactid.auxiliarySelectorLabels" -}}
app.kubernetes.io/name: {{ printf "%s-%s" (include "subactid.name" .context) .component | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
{{- end }}

{{- define "subactid.auxiliaryLabels" -}}
helm.sh/chart: {{ include "subactid.chart" .context }}
{{ include "subactid.auxiliarySelectorLabels" . }}
{{- if .context.Chart.AppVersion }}
app.kubernetes.io/version: {{ .context.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .context.Release.Service }}
app.kubernetes.io/part-of: subactid
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "subactid.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "subactid.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
The image reference. A digest, when set, wins over the tag: it is what the release signed.
*/}}
{{- define "subactid.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{/*
The upstream identity provider. For Keycloak the realm URL is enough: discovery, token and
admin users URLs derive from it. Each of the three can be set explicitly instead.
*/}}
{{- define "subactid.upstream.issuer" -}}
{{- trimSuffix "/" (required "upstream.issuer is required (or set upstream.metadataUrl, upstream.sponsorCheck.usersUrl and upstream.sponsorCheck.tokenUrl)" .Values.upstream.issuer) }}
{{- end }}

{{- define "subactid.upstream.metadataUrl" -}}
{{- if .Values.upstream.metadataUrl }}
{{- .Values.upstream.metadataUrl }}
{{- else }}
{{- printf "%s/.well-known/openid-configuration" (include "subactid.upstream.issuer" .) }}
{{- end }}
{{- end }}

{{- define "subactid.upstream.tokenUrl" -}}
{{- if .Values.upstream.sponsorCheck.tokenUrl }}
{{- .Values.upstream.sponsorCheck.tokenUrl }}
{{- else }}
{{- printf "%s/protocol/openid-connect/token" (include "subactid.upstream.issuer" .) }}
{{- end }}
{{- end }}

{{- define "subactid.upstream.usersUrl" -}}
{{- if .Values.upstream.sponsorCheck.usersUrl }}
{{- .Values.upstream.sponsorCheck.usersUrl }}
{{- else }}
{{- $parts := splitList "/realms/" (include "subactid.upstream.issuer" .) }}
{{- if ne (len $parts) 2 }}
{{- fail "upstream.sponsorCheck.usersUrl must be set: upstream.issuer is not a Keycloak realm URL of the form https://host/realms/<realm>, so the admin users collection cannot be derived from it." }}
{{- end }}
{{- printf "%s/admin/realms/%s/users" (first $parts) (last $parts) }}
{{- end }}
{{- end }}

{{/*
One optional setting, rendered only when its value is not empty, so that an explicit false or 0
is kept where `with` would drop it. A number is written whole, since a values file gives Helm a
float, which it would write as 1e+06. Called with a list of the variable name and the value.
*/}}
{{- define "subactid.env.optional" -}}
{{- $value := index . 1 -}}
{{- if ne (toString $value) "" }}
- name: {{ index . 0 }}
  value: {{ if or (kindIs "float64" $value) (kindIs "int64" $value) (kindIs "int" $value) }}{{ $value | int64 | toString | quote }}{{ else }}{{ $value | toString | quote }}{{ end }}
{{- end }}
{{- end }}

{{/*
Configuration shared by the server, the migrate job and the test pod: what migrate and doctor
read as well as the server. No secret values are rendered here.
*/}}
{{- define "subactid.env.common" -}}
- name: SubactId__Issuer
  value: {{ required "issuer is required: the absolute URL this control plane issues tokens as" .Values.issuer | quote }}
{{- if .Values.upstream.metadataUrl }}
- name: SubactId__UpstreamIdp__MetadataUrl
  value: {{ .Values.upstream.metadataUrl | quote }}
{{- else }}
# The server derives the discovery URL from the realm URL. Only one of Issuer and MetadataUrl is set.
- name: SubactId__UpstreamIdp__Issuer
  value: {{ include "subactid.upstream.issuer" . | quote }}
{{- end }}
- name: SubactId__UpstreamIdp__Audience
  value: {{ required "upstream.audience is required: the aud a subject token must carry" .Values.upstream.audience | quote }}
{{- include "subactid.env.optional" (list "SubactId__UpstreamIdp__SubjectTokenTypes" .Values.upstream.subjectTokenTypes) }}
{{- include "subactid.env.optional" (list "SubactId__UpstreamIdp__SponsorKeyClaim" .Values.upstream.sponsorKeyClaim) }}
{{- if eq (default "poll" .Values.upstream.sponsorCheck.mode) "signals" }}
{{- with .Values.upstream.sponsorCheck }}
{{- if or .usersUrl .tokenUrl .cacheTtl }}
{{- fail "upstream.sponsorCheck.usersUrl, tokenUrl and cacheTtl must be empty when upstream.sponsorCheck.mode is signals: the identity provider is not asked in that mode, and the server refuses them." }}
{{- end }}
{{- end }}
- name: SubactId__UpstreamIdp__SponsorCheck__Mode
  value: "signals"
{{- else }}
- name: SubactId__UpstreamIdp__SponsorCheck__UsersUrl
  value: {{ include "subactid.upstream.usersUrl" . | quote }}
- name: SubactId__UpstreamIdp__SponsorCheck__TokenUrl
  value: {{ include "subactid.upstream.tokenUrl" . | quote }}
- name: SubactId__UpstreamIdp__SponsorCheck__ClientId
  value: {{ required "upstream.sponsorCheck.clientId is required" .Values.upstream.sponsorCheck.clientId | quote }}
{{- include "subactid.env.optional" (list "SubactId__UpstreamIdp__SponsorCheck__CacheTtl" .Values.upstream.sponsorCheck.cacheTtl) }}
{{- end }}
{{- include "subactid.env.optional" (list "SubactId__UpstreamIdp__BackchannelLogout__Audience" .Values.upstream.backchannelLogout.audience) }}
{{- include "subactid.env.optional" (list "SubactId__Tokens__DefaultTaskTtl" .Values.tokens.defaultTaskTtl) }}
{{- include "subactid.env.optional" (list "SubactId__Tokens__DefaultTokenTtl" .Values.tokens.defaultTokenTtl) }}
{{- include "subactid.env.optional" (list "SubactId__Agents__MinTaskTtl" .Values.agents.minTaskTtl) }}
{{- include "subactid.env.optional" (list "SubactId__Agents__MaxTaskTtl" .Values.agents.maxTaskTtl) }}
{{- include "subactid.env.optional" (list "SubactId__Agents__MinTokenTtl" .Values.agents.minTokenTtl) }}
{{- include "subactid.env.optional" (list "SubactId__Agents__MaxTokenTtl" .Values.agents.maxTokenTtl) }}
{{- include "subactid.env.optional" (list "SubactId__AgentKeys__BlockPrivateNetworks" .Values.agentKeys.blockPrivateNetworks) }}
{{- include "subactid.env.optional" (list "SubactId__AllowInsecureHttp" .Values.allowInsecureHttp) }}
{{- include "subactid.env.optional" (list "SubactId__Tasks__SweepInterval" .Values.tasks.sweepInterval) }}
{{- include "subactid.env.optional" (list "SubactId__Tasks__SweepBatchSize" .Values.tasks.sweepBatchSize) }}
{{- include "subactid.env.optional" (list "SubactId__Tasks__Retention" .Values.tasks.retention) }}
{{- include "subactid.env.optional" (list "SubactId__Revocations__SignOutRetention" .Values.revocations.signOutRetention) }}
{{- include "subactid.env.optional" (list "SubactId__Audit__Partitions__MonthsAhead" .Values.audit.partitionMonthsAhead) }}
- name: ASPNETCORE_HTTP_PORTS
  value: {{ .Values.containerPort | quote }}
{{- with .Values.logging.minimumLevel }}
- name: Serilog__MinimumLevel__Default
  value: {{ . | quote }}
{{- end }}
{{- range $source, $level := .Values.logging.overrides }}
- name: Serilog__MinimumLevel__Override__{{ $source }}
  value: {{ $level | quote }}
{{- end }}
{{- end }}

{{/*
Configuration only the server reads: its credentials, the receivers, the audit sink and the
limits. SCIM and Shared Signals settings travel with their credentials, since the server refuses
one without the other, so they never reach the migrate job or the test pod.
*/}}
{{- define "subactid.env.server" -}}
{{- if .Values.admin.existingSecret }}
- name: SubactId__Admin__ApiKey
  valueFrom:
    secretKeyRef:
      name: {{ .Values.admin.existingSecret | quote }}
      key: {{ .Values.admin.existingSecretKey | quote }}
{{- end }}
{{- include "subactid.env.optional" (list "SubactId__Audit__Sink__Url" .Values.audit.sink.url) }}
{{- if .Values.audit.sink.existingSecret }}
- name: SubactId__Audit__Sink__BearerToken
  valueFrom:
    secretKeyRef:
      name: {{ .Values.audit.sink.existingSecret | quote }}
      key: {{ .Values.audit.sink.existingSecretKey | quote }}
{{- end }}
{{- include "subactid.env.optional" (list "SubactId__Audit__DrainInterval" .Values.audit.drainInterval) }}
{{- include "subactid.env.optional" (list "SubactId__Audit__DrainBatchSize" .Values.audit.drainBatchSize) }}
{{- include "subactid.env.optional" (list "SubactId__Audit__Checkpoint__Interval" .Values.audit.checkpointInterval) }}
{{- include "subactid.env.optional" (list "SubactId__Audit__Retention" .Values.audit.retention) }}
{{- include "subactid.env.optional" (list "SubactId__Audit__Aggregation__Enabled" .Values.audit.aggregation.enabled) }}
{{- include "subactid.env.optional" (list "SubactId__Audit__Aggregation__Window" .Values.audit.aggregation.window) }}
{{- include "subactid.env.optional" (list "SubactId__RateLimit__Enabled" .Values.rateLimit.enabled) }}
{{- include "subactid.env.optional" (list "SubactId__RateLimit__PermitsPerMinute" .Values.rateLimit.permitsPerMinute) }}
{{- include "subactid.env.optional" (list "SubactId__RateLimit__Burst" .Values.rateLimit.burst) }}
{{- include "subactid.env.optional" (list "SubactId__RateLimit__TrustedProxies" .Values.rateLimit.trustedProxies) }}
{{- include "subactid.env.optional" (list "SubactId__RateLimit__Signals__PermitsPerMinute" .Values.rateLimit.signals.permitsPerMinute) }}
{{- include "subactid.env.optional" (list "SubactId__RateLimit__Signals__Burst" .Values.rateLimit.signals.burst) }}
{{- include "subactid.env.optional" (list "SubactId__RateLimit__Introspection__PermitsPerMinute" .Values.rateLimit.introspection.permitsPerMinute) }}
{{- include "subactid.env.optional" (list "SubactId__RateLimit__Introspection__Burst" .Values.rateLimit.introspection.burst) }}
{{- include "subactid.env.optional" (list "SubactId__Overload__Enabled" .Values.overload.enabled) }}
{{- include "subactid.env.optional" (list "SubactId__Overload__ConcurrencyLimit" .Values.overload.concurrencyLimit) }}
{{- include "subactid.env.optional" (list "SubactId__Overload__QueueLimit" .Values.overload.queueLimit) }}
{{- include "subactid.env.optional" (list "SubactId__Overload__QueueTimeout" .Values.overload.queueTimeout) }}
{{- with .Values.scim }}
{{- if .existingSecret }}
- name: SubactId__Scim__BearerToken
  valueFrom:
    secretKeyRef:
      name: {{ .existingSecret | quote }}
      key: {{ .existingSecretKey | quote }}
{{- with .previousSecretKey }}
- name: SubactId__Scim__PreviousBearerToken
  valueFrom:
    secretKeyRef:
      name: {{ $.Values.scim.existingSecret | quote }}
      key: {{ . | quote }}
{{- end }}
{{- include "subactid.env.optional" (list "SubactId__Scim__SponsorKeyAttribute" .sponsorKeyAttribute) }}
{{- include "subactid.env.optional" (list "SubactId__Scim__MaxUsers" .maxUsers) }}
{{- else if or .previousSecretKey .sponsorKeyAttribute (ne (toString .maxUsers) "") }}
{{- fail "scim.previousSecretKey, sponsorKeyAttribute and maxUsers need scim.existingSecret: the SCIM receiver is off without its credential, and the server refuses its settings then." }}
{{- end }}
{{- end }}
{{- with .Values.ssf }}
{{- if .issuer }}
- name: SubactId__Ssf__Issuer
  value: {{ .issuer | quote }}
- name: SubactId__Ssf__Audience
  value: {{ required "ssf.audience is required with ssf.issuer: the audience every event must carry" .audience | quote }}
- name: SubactId__Ssf__BearerToken
  valueFrom:
    secretKeyRef:
      name: {{ required "ssf.existingSecret is required with ssf.issuer: the Secret holding the credential the transmitter presents" .existingSecret | quote }}
      key: {{ .existingSecretKey | quote }}
{{- with .previousSecretKey }}
- name: SubactId__Ssf__PreviousBearerToken
  valueFrom:
    secretKeyRef:
      name: {{ $.Values.ssf.existingSecret | quote }}
      key: {{ . | quote }}
{{- end }}
{{- else if or .audience .existingSecret .previousSecretKey }}
{{- fail "ssf.audience, existingSecret and previousSecretKey need ssf.issuer: the Shared Signals receiver is off without a transmitter to trust, and the server refuses its settings then." }}
{{- end }}
{{- end }}
{{- end }}

{{/*
extraEnv, for every container. A Subact ID setting is refused here: each has a value of its own,
and a second definition of one would be ambiguous.
*/}}
{{- define "subactid.env.extra" -}}
{{- range .Values.extraEnv }}
{{- if regexMatch "^((aspnetcore|dotnet)_)?subactid__" (lower .name) }}
{{- fail (printf "extraEnv must not set %s: every Subact ID setting has a value of its own in the chart; docs/kubernetes.md lists them." .name) }}
{{- end }}
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Database connection strings, read from Secrets. The server uses database.existingSecret. The
migrate job uses database.migration.existingSecret when set, so the server cannot change the schema.
*/}}
{{- define "subactid.env.database" -}}
- name: SubactId__Database__ConnectionString
  valueFrom:
    secretKeyRef:
      name: {{ required "database.existingSecret is required: the name of a Secret holding the connection string" .Values.database.existingSecret | quote }}
      key: {{ .Values.database.existingSecretKey | quote }}
{{- end }}

{{- define "subactid.env.migrationDatabase" -}}
{{- if .Values.database.migration.existingSecret }}
- name: SubactId__Database__MigrationConnectionString
  valueFrom:
    secretKeyRef:
      name: {{ .Values.database.migration.existingSecret | quote }}
      key: {{ .Values.database.migration.existingSecretKey | quote }}
{{- end }}
{{- end }}

{{/*
Signing keys, as files. Every configured key is published in the JWKS. activeKid picks the signer.
*/}}
{{- define "subactid.env.signing" -}}
{{- $mount := trimSuffix "/" .Values.signing.mountPath -}}
{{- $keys := .Values.signing.keys -}}
{{- if not $keys -}}
{{- fail "signing.keys must list at least one key within signing.existingSecret" -}}
{{- end -}}
{{- if and (gt (len $keys) 1) (not .Values.signing.activeKid) -}}
{{- fail "signing.activeKid is required when more than one key is configured: with several keys the signer is chosen explicitly, never by order." -}}
{{- end -}}
{{- range $index, $key := $keys }}
- name: SubactId__Signing__Keys__{{ $index }}__Path
  value: {{ printf "%s/%s" $mount (required "each entry of signing.keys needs a key within the Secret" $key.key) | quote }}
{{- with $key.kid }}
- name: SubactId__Signing__Keys__{{ $index }}__Kid
  value: {{ . | quote }}
{{- end }}
{{- end }}
{{- with .Values.signing.activeKid }}
- name: SubactId__Signing__ActiveKid
  value: {{ . | quote }}
{{- end }}
{{- end }}

{{- /*
Builds network policy peers as data and renders them with toYaml.
*/}}
{{- define "subactid.networkPolicy.peers" -}}
{{- $peers := list -}}
{{- if or .podSelector .namespaceSelector -}}
{{- $selector := dict -}}
{{- with .namespaceSelector }}{{ $selector = merge $selector (dict "namespaceSelector" .) }}{{ end -}}
{{- with .podSelector }}{{ $selector = merge $selector (dict "podSelector" .) }}{{ end -}}
{{- $peers = append $peers $selector -}}
{{- end -}}
{{- range .cidrs }}{{ $peers = append $peers (dict "ipBlock" (dict "cidr" .)) }}{{ end -}}
{{- toYaml $peers -}}
{{- end -}}
