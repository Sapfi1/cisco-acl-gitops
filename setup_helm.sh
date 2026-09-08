#!/usr/bin/env bash
set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="$REPO_ROOT/helm/cisco-acl-chart"

echo "==> 1. Создание структуры папок Helm..."
mkdir -p "$CHART_DIR/templates"

echo "==> 2. Генерация Chart.yaml..."
cat << 'EOF' > "$CHART_DIR/Chart.yaml"
apiVersion: v2
name: cisco-acl-chart
description: Helm chart for Cisco ACL GitOps Automation Web Application
type: application
version: 0.1.0
appVersion: "1.0.0"
EOF

echo "==> 3. Генерация values.yaml..."
cat << 'EOF' > "$CHART_DIR/values.yaml"
replicaCount: 1

image:
  repository: cisco-acl-gitops-web
  tag: latest
  pullPolicy: IfNotPresent

service:
  type: NodePort
  port: 5000
  nodePort: 30080

persistence:
  enabled: true
  storageClass: standard
  accessMode: ReadWriteOnce
  size: 1Gi

ciscoCredentials:
  user: "admin"
  password: "CiscoPassword123"
  enableSecret: "CiscoEnable123"

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi
EOF

echo "==> 4. Генерация шаблона PVC (pvc.yaml)..."
cat << 'EOF' > "$CHART_DIR/templates/pvc.yaml"
{{- if .Values.persistence.enabled }}
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {{ .Release.Name }}-data-pvc
  labels:
    app: {{ .Release.Name }}
spec:
  accessModes:
    - {{ .Values.persistence.accessMode }}
  resources:
    requests:
      storage: {{ .Values.persistence.size }}
{{- end }}
EOF

echo "==> 5. Генерация шаблона Secret (secret.yaml)..."
cat << 'EOF' > "$CHART_DIR/templates/secret.yaml"
apiVersion: v1
kind: Secret
metadata:
  name: {{ .Release.Name }}-cisco-secrets
  labels:
    app: {{ .Release.Name }}
type: Opaque
stringData:
  CISCO_USER: {{ .Values.ciscoCredentials.user | quote }}
  CISCO_PASSWORD: {{ .Values.ciscoCredentials.password | quote }}
  CISCO_ENABLE: {{ .Values.ciscoCredentials.enableSecret | quote }}
EOF

echo "==> 6. Генерация шаблона Deployment (deployment.yaml)..."
cat << 'EOF' > "$CHART_DIR/templates/deployment.yaml"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-web
  labels:
    app: {{ .Release.Name }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app: {{ .Release.Name }}
  template:
    metadata:
      labels:
        app: {{ .Release.Name }}
    spec:
      containers:
        - name: web
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - containerPort: 5000
          envFrom:
            - secretRef:
                name: {{ .Release.Name }}-cisco-secrets
          volumeMounts:
            - name: app-storage
              mountPath: /app/data
            - name: configs-storage
              mountPath: /app/configs
          resources:
            {{- toYaml .Values.resources | nindent 12 }}
      volumes:
        - name: app-storage
          persistentVolumeClaim:
            claimName: {{ .Release.Name }}-data-pvc
        - name: configs-storage
          emptyDir: {}
EOF

echo "==> 7. Генерация шаблона Service (service.yaml)..."
cat << 'EOF' > "$CHART_DIR/templates/service.yaml"
apiVersion: v1
kind: Service
metadata:
  name: {{ .Release.Name }}-service
  labels:
    app: {{ .Release.Name }}
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: {{ .Values.service.port }}
      targetPort: 5000
      nodePort: {{ .Values.service.nodePort }}
  selector:
    app: {{ .Release.Name }}
EOF

echo "==> 8. Отправка изменений в Git..."
cd "$REPO_ROOT"
git add helm/
git commit -m "feat: Automate Helm chart creation for Cisco ACL stack" || echo "Нет новых изменений для коммита"
git push origin main

echo "==> Готово! Helm-чарт сформирован и отправлен в репозиторий."