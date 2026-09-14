# Cisco ACL GitOps Automation & Monitoring Platform

Дипломный проект по автоматизации управления конфигурациями сетей Cisco (Access Control Lists) с использованием современных DevOps-инструментов, методологии GitOps и непрерывного мониторинга.

---

## 🚀 Архитектура и стек технологий

Проект реализует полный цикл CI/CD и развертывания сетевого веб-приложения в Kubernetes с интеграцией систем сбора метрик.

* **Оркестрация и контейнеризация:** Docker, Kubernetes (Minikube), Helm Charts.
* **CI/CD & GitOps:** GitHub Actions (Self-hosted runner).
* **Автоматизация и сети:** Python (Flask), Ansible (коллекция `cisco.ios`), Git-хранилище конфигураций.
* **Мониторинг и наблюдаемость:** Prometheus, Grafana, Ingress NGINX.

---

## 📁 Структура репозитория

```text
cisco-acl-gitops/
├── .github/workflows/   # CI/CD пайплайны GitHub Actions (deploy.yml)
├── ansible/             # Playbooks и роли для настройки сетевых устройств
├── app/                 # Исходный код веб-приложения (app.py, Dockerfile, requirements.txt)
├── configs/             # Хранилище сгенерированных конфигураций Cisco ACL
├── helm/                # Helm-чарт для развертывания приложения (cisco-acl-chart)
├── docker-compose.yml   # Дополнительная конфигурация для локального запуска
└── setup_helper.sh      # Вспомогательные скрипты развертывания