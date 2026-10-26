{{/* Base name. */}}
{{- define "CodeSentinal..name" -}}CodeSentinal.{{- end -}}

{{/* Common labels (component passed via dict). */}}
{{- define "CodeSentinal..labels" -}}
app.kubernetes.io/part-of: CodeSentinal.
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* Service account name. */}}
{{- define "CodeSentinal..serviceAccountName" -}}
{{- default "CodeSentinal.-sa" .Values.serviceAccount.name -}}
{{- end -}}

{{/* Component selector labels: include this template with a two-item list
     (root context, component name). */}}
{{- define "CodeSentinal..componentSelector" -}}
app.kubernetes.io/name: CodeSentinal.
app.kubernetes.io/component: {{ .component }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end -}}
