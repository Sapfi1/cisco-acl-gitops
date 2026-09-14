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

⚙️ Основной функционал
Веб-интерфейс для управления ACL: Приложение на базе Python/Flask обрабатывает запросы, формирует правила доступа для оборудования Cisco и автоматизирует их версионирование.
GitOps Деплой через GitHub Actions: Любое изменение в ветке main автоматически триггерит пайплайн, который линтит Helm-чарты, собирает Docker-образ локально и обновляет релиз в кластере Minikube.
Интегрированный мониторинг: Развертывание стека kube-prometheus-stack (Prometheus + Grafana) для отслеживания состояния подов, потребления ресурсов и метрик приложения.
Маршрутизация (Ingress): Доступ к веб-интерфейсу, Grafana и Prometheus через настроенные Ingress-маршруты и NodePort сервисы.

🛠️ Инструкция по развертыванию (Quick Start)
1. Клонирование репозитория
Bash
git clone [https://github.com/Sapfi1/cisco-acl-gitops.git](https://github.com/Sapfi1/cisco-acl-gitops.git)
cd cisco-acl-gitops
2. Запуск деплоя через GitHub Actions
Пайплайн настроен на работу с локальным self-hosted раннером. Для запуска деплоя достаточно сделать пуш в ветку main или запустить workflow вручную во вкладке Actions на GitHub:
Bash
git commit --allow-empty -m "chore: trigger deployment"
git push origin main
3. Проверка статуса в Kubernetes
Bash
# Проверка подов приложения и мониторинга
kubectl get pods -A

# Проверка сервисов и NodePort
kubectl get svc -A
📊 Доступ к сервисам
Веб-приложение Cisco ACL: Доступно через NodePort 30500 или настроенный Ingress (cisco.local).
Grafana (Дашборды): Доступна на порту 30300 (файл values.yaml). Логин/Пароль по умолчанию: admin / admin.
Prometheus: Сбор метрик и мониторинг состояния кластера (NodePort 30900).
