# 🚀 Автоматизация сервера: HestiaCP, Grafana, Prometheus, Loki, Fail2Ban, Firewall

> **Универсальный Bash-скрипт для быстрого развёртывания и настройки современной серверной инфраструктуры мониторинга и управления на Ubuntu/Debian.**

----

## 📋 Описание

Этот скрипт автоматически устанавливает и настраивает:
- [HestiaCP](https://hestiacp.com/) — удобная панель управления сервером
- [Grafana](https://grafana.com/), [Prometheus](https://prometheus.io/), [Node Exporter](https://prometheus.io/docs/guides/node-exporter/), [Pushgateway](https://prometheus.io/docs/practices/pushing/) — инструменты мониторинга
- [Loki](https://grafana.com/oss/loki/) и [Promtail](https://grafana.com/docs/loki/latest/clients/promtail/) — сбор и просмотр логов
- [Fail2Ban](https://www.fail2ban.org/) — защита от брутфорса и бот-атак
- Firewall (iptables) — базовая защита сервера

Скрипт подойдет для быстрого старта любого VPS или выделенного сервера.

---

## 🧩 Функционал

1. **Проверка root-доступа**
2. **Удаление старых версий Grafana (если были)**
3. **Установка системных и дополнительных пакетов**
4. **Установка HestiaCP**
5. **Настройка и активация iptables firewall**
6. **Установка и настройка Fail2Ban**
7. **Установка Grafana**
8. **Установка Prometheus, Node Exporter, Pushgateway**
9. **Установка Loki и Promtail**
10. **Экспортер метрик Fail2Ban для Prometheus**
11. **Автоматическая настройка и импорт дашбордов в Grafana**
12. **Вывод информации по доступу ко всем сервисам**

---

## ⚡ Быстрый старт

1. **Скопируйте или скачайте скрипт на сервер:**
    ```bash
    git clone https://github.com/Traffic-Connect/tc-fast-setup .
    chmod +x script.sh
    ```

2. **Запустите скрипт с правами root:**
    ```bash
    sudo ./script.sh
    ```

3. **Дождитесь завершения работы.**
   - Весь процесс занимает 10–30 минут, в зависимости от мощности сервера и скорости сети.

4. **После завершения вы получите ссылки и логины для всех сервисов в консоли.**

---

## 🖥️ Получаемые сервисы

- **HestiaCP:** `http://<your_server_ip>:8083`
- **Grafana:** `http://<your_server_ip>:3000`
- **Prometheus:** `http://<your_server_ip>:9090`
- **Loki:** `http://<your_server_ip>:3100`
- **Pushgateway:** `http://<your_server_ip>:9091`

> Пароль от HestiaCP (admin) находится в файле:  
> `/usr/local/hestia/data/users/admin/password.conf`  
>  
> Данные для входа в Grafana:  
> Логин: **Trafficadmin**  
> Пароль: **admin** (настоятельно рекомендуется сменить после первого входа!)

---

## 🔒 Безопасность

- **Сразу смените все пароли администратора!**
- Для повышенной безопасности ограничьте доступ по SSH через firewall и используйте Fail2Ban.
- Проверяйте, что нужные порты открыты и на уровне облачного провайдера.

---

## ⚙️ Требования

- Поддерживаемые системы: **Ubuntu 22.04+, Debian 10+** (рекомендуется использовать свежую LTS версию)
- Права root (`sudo`)
- Минимум 2 ГБ RAM (рекомендуется 4+ ГБ)

---

## 📦 Список устанавливаемого ПО

- HestiaCP
- Grafana
- Prometheus
- Node Exporter
- Pushgateway
- Loki
- Promtail
- Fail2Ban
- iptables, iptables-persistent
- Python3, pip и прометей-экспортер для fail2ban

---

## 🏁 После установки

- Зайдите на любой из сервисов по указанному адресу в консоли.
- **Обязательно смените пароли по умолчанию!**
- Для HestiaCP пароль можно посмотреть так:
    ```bash
    cat /usr/local/hestia/data/users/admin/password.conf
    ```
- Рекомендуется настроить регулярные обновления:
    ```bash
    apt update && apt upgrade -y
    ```

---

## 📝 FAQ

- **Скрипт не запускается:**  
  Убедитесь, что вы используете права root: `sudo -i` или `sudo ./script.sh`

- **Порты не открыты:**  
  Не забудьте открыть необходимые порты и на уровне firewall облачного провайдера!

- **Хочу добавить свой дашборд или источник данных в Grafana:**  
  Вы можете сделать это через веб-интерфейс Grafana (по адресу сервера:3000).

---

## 🧑‍💻 Автор

- **TrafficConnect**

---

## 🤝 Лицензия

Используйте и модифицируйте свободно под свои нужды!  
Если будут предложения по улучшению — создавайте PR или пишите в Issues.

---

**Удачной автоматизации!**
