# PixelTunnel — Open-Source Windows Unlocker

Лёгкий и полностью открытый клиент для Windows (C# / WPF / .NET Framework 4.x) с точечной маршрутизацией трафика (Split-Tunneling).

## Что работает бесплатно и бессрочно
- **Antigravity 2.0, IDE и Терминал** — вход, плагины, MCP-серверы и агенты
- **ChatGPT, Claude, Cursor и нейросети** — Copilot, Midjourney, Suno, ElevenLabs, Perplexity
- **Telegram, Spotify и соцсети** — Telegram (включая Desktop), Spotify, Instagram, X, LinkedIn, Canva
- **Совместимость с Zapret / GoodbyeDPI** — в бесплатном режиме домены YouTube и Discord идут напрямую (`DIRECT`) и не конфликтуют со сторонними обходами

Для **YouTube & Discord** без сторонних утилит и полноценного VPN на **iPhone / Android / ПК** можно подключить персональный ключ из [@p1xivpn_bot](https://t.me/p1xivpn_bot).

## Сборка из исходников (за 5 секунд)
Никаких сторонних зависимостей — используется только встроенный компилятор Windows `.NET Framework 4.x`:

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

На выходе появится готовый `PixelTunnel.exe` в корне репозитория.

## Безопасность и проверка
- Весь код клиента открыт в папке `src/` (`PixelTunnelNext.cs` и `PixelCoreEngineV3.cs`).
- Обновления внутри приложения проверяются по цифровой подписи **ECDSA P-256** и хэшу **SHA-256**.
- Сборка также автоматически проверяется через [GitHub Actions](.github/workflows/build.yml).
