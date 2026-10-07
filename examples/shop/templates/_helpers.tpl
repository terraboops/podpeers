{{- define "shop.labels" -}}
app.kubernetes.io/name: shop
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "shop.fqdn" -}}
{{ .Release.Name }}-{{ .component }}.{{ .ns }}.svc.cluster.local
{{- end -}}
