# PixelTunnel v1.9.0 — Open-Source Windows Unlocker

Лёгкий и полностью открытый клиент для Windows (C# / WPF / .NET Framework 4.x) с точечной маршрутизацией трафика (Split-Tunneling) и мультиплексированным транспортом **PWP-3**.

## Что нового в v1.9.0
- **Zero-Secret Client & Динамический манифест**: удалены любые зашитые триал-ключи, UUID и общие секреты; конфигурация и ключи узлов загружаются динамически из подписанного ECDSA P-256 манифеста `nodes_v3.enc` с защитой от отката версии (`ManifestVersion`) и проверкой `issued_utc`.
- **Строгий TLS / SPKI Pinning & Anti-DPI**: отключён открытый HTTP fallback `:25442` и самоподписанный TLS fallback (`_allowSelfSignedFallback = false`); проверка сертификата по цепочке TLS и pinned SPKI SHA-256, ротация `MuxSession` до переполнения счётчика шифраторных блоков.
- **Прокси, IPv6 & Локальная безопасность**: закрыт таймер-лик в `BridgeDirectAsync`, добавлена поддержка IPv4-mapped IPv6 и Telegram IPv6-префиксов, точное сопоставление доменов (`HostMatchesDomain`), строгая проверка `Host` для локального API `/__pixelcore/status` и `0x00`-метода в SOCKS5.
- **Надёжность WinINet, Telegram, Updater & CLI**: `RunOnce` (`PixelTunnelProxyReset`) аварийный сброс прокси после сбоя питания, динамическая 1-клик настройка Telegram SOCKS5, верификация обновлений по ECDSA P-256 + SHA-256 и корректные переменные `ALL_PROXY=socks5h://` / `NO_PROXY` для CLI.

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
