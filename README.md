# Antigravity Unlocker (`PixelTunnel v1.4`)

Автономный патчер и микро-туннель для **Google Antigravity IDE** на Windows.
Без установки сетевых драйверов (`Wintun` / `WinDivert`), без 35-мегабайтных `xray.exe` / `sing-box` и без проксирования всей системы.

Вес клиента — **287 КБ** (чистый C# / .NET Framework 4.x, встроенный в стандартную Windows).

---

## Зачем это нужно (простым языком)

После последних обновлений Google Antigravity IDE обычные VPN, Nova, GoodbyeDPI и правки `hosts` перестали спасать от бесконечного редиректа входа в браузере и отвала агента (`inexigible_tiers` / `Region Restricted`).

**AG Unlocker решает проблему точечно на уровне самой IDE:**

1. **Авто-патч `language_server_windows_x64.exe` (Watchdog):**
   Автоматически вырезает проверки региона (`inexigible_tiers` / `inexigibleTiers`) в бинарнике языкового сервера. Если Antigravity обновилась в фоне и перезаписала файлы — Watchdog сам пропатчит свежий бинарник за 3 секунды без вашего участия.
2. **Свой микро-движок `PixelCore (PWP-1)` (26 КБ):**
   Никаких сторонних консольных комбайнов на 35 МБ. Заворачивает через защищённый TLS-туннель (`Schannel` + фрагментация первого пакета от ТСПУ) только OAuth2-авторизацию Google (`accounts.google.com`, `oauth2.googleapis.com`) и стриминг агента (`daily-cloudcode-pa.googleapis.com`, Gemini, Claude, OpenAI).
3. **Авто-очистка мусора от старых обходов:**
   При старте сам гасит конфликтующие драйверы/службы (`GoodbyeDPI`, `WinDivert`, `zapret`, `ProksiFi`) и комментирует кривые IP Google/Gemini в `C:\Windows\System32\drivers\etc\hosts`, из-за которых намертво виснет вход.
4. **Прямой доступ к РФ-сайтам и нулевой пинг:**
   В режиме `Только Antigravity IDE` системный прокси Windows **вообще не трогается**. Локалхост, банки, Госуслуги, рабочие корпоративные VPN и игры работают напрямую.

---

## Как запустить

1. Скачайте [**`PixelTunnel_Antigravity_v1.4.zip`**](https://github.com/keenfolk1-lgtm/antigravity-unlocker/releases/latest) (или отдельно `PixelTunnel.exe`) из раздела [**Releases**](https://github.com/keenfolk1-lgtm/antigravity-unlocker/releases/latest).
2. Запустите `PixelTunnel.exe`.
3. Нажмите **«ПОДКЛЮЧИТЬ И ОТКРЫТЬ ANTIGRAVITY»**.

---

## Ответы для скептиков («не хочу качать непонятный exe»)

* **287 КБ чистого C# (.NET 4.x):** легко проверяется любым стандартным анализатором, не тянет за собой скрытые гигабайтные рантаймы и сторонние прокси-ядра.
* **Никаких драйверов ядра:** не ставит виртуальные сетевые карты и не лезет в ядро Windows (работает строго в `User-mode`).
* **Бэкап оригиналов:** перед патчем `language_server_windows_x64.exe` рядом всегда сохраняется чистая копия `.bak`.
* **Канал и обновления:** [@pixel_antigravity_fix](https://t.me/pixel_antigravity_fix)
