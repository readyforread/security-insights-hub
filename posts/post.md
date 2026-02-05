---
title: Практическое руководство по тестированию уязвимости CVE-2024-XXXX
date: 2024-01-15
author: Алексей Петров
cvss: 7.5
cve: CVE-2024-XXXX
tags: [безопасность, тестирование, веб-уязвимости, эксплуатация]
image: https://images.unsplash.com/photo-1555949963-aa79dcee981c
---

Пошаговое руководство по обsаружению и тестированию уязвимости CVE-2024-XXXX в CMS WebCraft, позволяющей выполнять произвольный код через недостаточную валидацию загружаемых файлов.

## Подготовка тестовой среды

Перед началом тестирования необходимо развернуть уязвимую версию WebCraft CMS (до версии 3.4.2) в изолированной среде.

### Установка тестового окружения

### Код для развертывания уязвимой версии через Docker

```dockerfile
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    apache2 \
    php7.4 \
    libapache2-mod-php7.4 \
    unzip

COPY webcraft-v3.4.1.zip /var/www/html/

RUN unzip /var/www/html/webcraft-v3.4.1.zip -d /var/www/html/

EXPOSE 80

CMD ["apachectl", "-D", "FOREGROUND"]
