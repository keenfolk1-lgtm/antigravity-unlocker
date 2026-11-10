# Antigravity Unlocker (`PixelTunnel v1.4`)

[![Release](https://img.shields.io/github/v/release/keenfolk1-lgtm/antigravity-unlocker?style=flat-square&color=blue)](https://github.com/keenfolk1-lgtm/antigravity-unlocker/releases/latest)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-lightgrey?style=flat-square)](https://github.com/keenfolk1-lgtm/antigravity-unlocker)
[![Size](https://img.shields.io/badge/client%20size-287%20KB-success?style=flat-square)](https://github.com/keenfolk1-lgtm/antigravity-unlocker)
[![Telegram](https://img.shields.io/badge/Updates-Telegram%20Channel-2CA5E0?style=flat-square&logo=telegram)](https://t.me/pixel_antigravity_fix)

Автономный патчер и микро-туннель для **Google Antigravity IDE** на Windows.
Без установки сетевых драйверов (`Wintun` / `WinDivert`), без 35-мегабайтных комбайнов (`xray` / `sing-box`) и без перехвата всей системы.

Клиент весит всего **287 КБ** (чистый C# / .NET Framework 4.x, нативно встроенный в любую стандартную Windows 10/11).

---

## 🔍 Какие ошибки и симптомы решает (Fixes & Errors)

Если у вас наблюдается что-либо из списка ниже — этот анлокер создан ровно под эти проблемы:

* `inexigible_tiers` / `inexigibleTiers` в логах языкового сервера.
* **Бесконечный редирект авторизации:** после логина через Google в браузере страница зависает или выдаёт `Connection reset` / `Не удается получить доступ к сайту`.
* Ошибки региона: *"Your account is currently not eligible"*, *"Region not supported"* при попытке подключить Gemini / Claude моделями в Antigravity.
* **Слет авторизации после каждого фонового обновления Antigravity IDE:** когда Google обновляет `language_server_windows_x64.exe`, ручные байт-патчи и моды затираются.
* Обрывы генерации и зависание стриминга на длинных промптах из-за блокировок ТСПУ (DPI) по протоколу HTTP/2 и gRPC.
* Поломанные локальные DNS и зависший файл `C:\Windows\System32\drivers\etc\hosts` после использования кривых скриптов и чужих фиксов.

---

## ⚡ Как это работает под капотом

1. **Auto-Patch Watchdog (фоновый авто-патчер):**
   При старте и в фоне непрерывно отслеживает `language_server_windows_x64.exe`. Как только Antigravity обновляется и скачивает новый бинарник — Watchdog за 3 секунды на лету вырезает региональные проверки `inexigible_tiers`, создает бэкап `.bak` и восстанавливает мост. Больше никаких повторных ручных патчей.
2. **Микро-движок `PixelCore (PWP-1)` (26 КБ):**
   Вместо тяжелых сторонних VPN-ядер на Go, здесь работает легковесный нативный C#-движок. Он перехватывает **исключительно** трафик Antigravity IDE:
   - Авторизация Google OAuth2 (`accounts.google.com`, `oauth2.googleapis.com`)
   - Стриминг агента (`daily-cloudcode-pa.googleapis.com`, Gemini, Claude, OpenAI)
3. **Обход блокировок ТСПУ:**
   Использует нативный TLS-стек Windows (`Schannel`) с фрагментацией первого пакета `ClientHello`, благодаря чему туннель не детектируется и не режется DPI-фильтрами провайдеров.
4. **Умный чистильщик чужих конфликтов:**
   Перед запуском автоматически останавливает конфликтующие службы и драйверы (`GoodbyeDPI`, `WinDivert`, `zapret`, `ProksiFi`) и аккуратно комментирует мусорные строки в `hosts`, которые ломают обращение к серверам Google.
5. **Нулевое влияние на остальной трафик:**
   Системный сетевой стек и прокси Windows в режиме *"Только Antigravity"* **не затрагиваются**. Российские сервисы, банки, Госуслуги, YouTube/Discord (если у вас стоит свой сетап) и корпоративные VPN продолжают работать напрямую.

---

## 🚀 Быстрый старт

1. Скачайте [**`PixelTunnel_Antigravity_v1.4.zip`**](https://github.com/keenfolk1-lgtm/antigravity-unlocker/releases/latest) (или отдельно `PixelTunnel.exe`) из [**Releases**](https://github.com/keenfolk1-lgtm/antigravity-unlocker/releases/latest).
2. Распакуйте и запустите `PixelTunnel.exe`.
3. Нажмите **«ПОДКЛЮЧИТЬ И ОТКРЫТЬ ANTIGRAVITY»**.
4. Вход в аккаунт подхватится автоматически.

---

## 🛡️ Прозрачность и безопасность

* **Без драйверов ядра:** не ставит виртуальные сетевые адаптеры (`TUN/TAP`), работает строго в User-mode.
* **Без скрытых процессов:** при выходе из трея туннель полностью выгружается из памяти без висящих фоновых демонов.
* **Бэкап:** перед любым изменением файлов IDE создается резервная копия `.bak`.
* **Официальный Telegram-канал проекта:** [@pixel_antigravity_fix](https://t.me/pixel_antigravity_fix)
