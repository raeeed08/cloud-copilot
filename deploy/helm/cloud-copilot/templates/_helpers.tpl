{{- define "cc.name" -}}{{ .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end }}
{{- define "cc.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}{{ .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end }}
{{- end }}
{{- define "cc.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{ include "cc.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: cloud-copilot
{{- end }}
{{- define "cc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
{{- define "cc.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}{{ default (include "cc.fullname" .) .Values.serviceAccount.name }}
{{- else }}{{ default "default" .Values.serviceAccount.name }}{{- end }}
{{- end }}
{{- define "cc.image" -}}
{{- if .Values.image.digest }}{{ printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}{{ printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}{{- end }}
{{- end }}
{{- define "cc.secretName" -}}
{{- if .Values.secrets.create }}{{ include "cc.fullname" . }}{{- else }}{{ .Values.secrets.existingSecret }}{{- end }}
{{- end }}
{{/* Shared pod spec pieces */}}
{{- define "cc.envFrom" -}}
- configMapRef:
    name: {{ include "cc.fullname" . }}
- secretRef:
    name: {{ include "cc.secretName" . }}
    optional: true
{{- end }}
{{- define "cc.dbEnv" -}}
{{- if .Values.postgresql.enabled }}
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ default (printf "%s-postgresql" .Release.Name) .Values.postgresql.auth.existingSecret }}
      key: password
- name: DATABASE_URL
  value: "postgresql+psycopg://{{ .Values.postgresql.auth.username }}:$(DB_PASSWORD)@{{ .Release.Name }}-postgresql:5432/{{ .Values.postgresql.auth.database }}"
{{- end }}
{{- end }}
