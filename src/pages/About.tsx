import { Header } from "@/components/Header";
import { Footer } from "@/components/Footer";
import { Shield, Target, Users, BookOpen } from "lucide-react";

const About = () => {
  return (
    <div className="min-h-screen flex flex-col">
      <Header />

      <main className="flex-1">
        {/* Hero */}
        <section className="relative py-16 md:py-24 overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_hsl(var(--primary)/0.15),_transparent_50%)]" />
          <div className="container relative">
            <div className="max-w-3xl mx-auto text-center space-y-6">
              <h1 className="text-3xl md:text-4xl lg:text-5xl font-bold">
                О <span className="text-gradient">SecureBlog</span>
              </h1>
              <p className="text-lg text-muted-foreground">
                Ваш надёжный источник информации о кибербезопасности
              </p>
            </div>
          </div>
        </section>

        {/* Content */}
        <section className="py-12 md:py-16">
          <div className="container max-w-4xl">
            <div className="cyber-card p-6 md:p-10 space-y-8">
              <div className="space-y-4">
                <h2 className="text-xl font-bold flex items-center gap-2">
                  <Shield className="h-5 w-5 text-primary" />
                  Наша миссия
                </h2>
                <p className="text-muted-foreground leading-relaxed">
                  SecureBlog был создан с целью повышения осведомлённости в
                  области информационной безопасности. Мы анализируем актуальные
                  уязвимости, разбираем техники атак и предоставляем практические
                  рекомендации по защите систем.
                </p>
              </div>

              <div className="space-y-4">
                <h2 className="text-xl font-bold flex items-center gap-2">
                  <Target className="h-5 w-5 text-primary" />
                  Что мы публикуем
                </h2>
                <ul className="space-y-3 text-muted-foreground">
                  <li className="flex items-start gap-2">
                    <span className="text-primary mt-1">▹</span>
                    <span>
                      <strong className="text-foreground">Анализ CVE</strong> —
                      детальный разбор критических уязвимостей с оценкой CVSS
                    </span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-primary mt-1">▹</span>
                    <span>
                      <strong className="text-foreground">Техники атак</strong> —
                      объяснение методов, используемых злоумышленниками
                    </span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-primary mt-1">▹</span>
                    <span>
                      <strong className="text-foreground">Рекомендации</strong> —
                      практические советы по защите и митигации рисков
                    </span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-primary mt-1">▹</span>
                    <span>
                      <strong className="text-foreground">Инструменты</strong> —
                      обзоры решений для аудита и мониторинга безопасности
                    </span>
                  </li>
                </ul>
              </div>

              <div className="space-y-4">
                <h2 className="text-xl font-bold flex items-center gap-2">
                  <Users className="h-5 w-5 text-primary" />
                  Для кого этот блог
                </h2>
                <p className="text-muted-foreground leading-relaxed">
                  Наши материалы будут полезны специалистам по информационной
                  безопасности, DevOps-инженерам, системным администраторам,
                  разработчикам и всем, кто интересуется защитой IT-инфраструктуры.
                </p>
              </div>

              <div className="space-y-4">
                <h2 className="text-xl font-bold flex items-center gap-2">
                  <BookOpen className="h-5 w-5 text-primary" />
                  О CVSS
                </h2>
                <p className="text-muted-foreground leading-relaxed">
                  Common Vulnerability Scoring System (CVSS) — это открытый стандарт
                  для оценки критичности уязвимостей. Шкала от 0.0 до 10.0:
                </p>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 pt-2">
                  <div className="text-center p-3 rounded bg-[hsl(var(--cvss-none))]">
                    <div className="font-mono text-sm font-bold">0.0</div>
                    <div className="text-xs">None</div>
                  </div>
                  <div className="text-center p-3 rounded bg-[hsl(var(--cvss-low))]">
                    <div className="font-mono text-sm font-bold">0.1-3.9</div>
                    <div className="text-xs">Low</div>
                  </div>
                  <div className="text-center p-3 rounded bg-[hsl(var(--cvss-medium))] text-black">
                    <div className="font-mono text-sm font-bold">4.0-6.9</div>
                    <div className="text-xs">Medium</div>
                  </div>
                  <div className="text-center p-3 rounded bg-[hsl(var(--cvss-high))]">
                    <div className="font-mono text-sm font-bold">7.0-8.9</div>
                    <div className="text-xs">High</div>
                  </div>
                  <div className="text-center p-3 rounded bg-[hsl(var(--cvss-critical))]">
                    <div className="font-mono text-sm font-bold">9.0-10.0</div>
                    <div className="text-xs">Critical</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
};

export default About;
