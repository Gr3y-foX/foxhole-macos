# foxhole-macos — PF/DNS/VPN Handoff Note
**Date:** 2026-05-04  
**Project:** [foxhole-macos](https://github.com/Gr3y-foX/foxhole-macos)  
**Context:** macOS hardening script — DNS leak prevention layer + ClearVPN bridge failure

---

## 1. Что было сделано

### 1.1 DNS Leak Prevention (pf anchor)
- Создан LaunchDaemon: `com.hardening.pf.dnsleak.plist`
- Создан anchor файл: `/etc/pf.anchors/com.hardening.dnsleak`
- Логика правил (в порядке выполнения):
  1. `pass quick on lo0 all` — разрешить loopback (нужно для dnscrypt)
  2. `pass quick inet6 proto icmp6 all` — RFC 4890
  3. `pass out quick proto {udp tcp} to 9.9.9.9` — whitelist Quad9 (любой порт)
  4. `pass out quick proto {udp tcp} to 149.112.112.112` — whitelist Quad9 secondary
  5. `block out quick proto {udp tcp} from any to any port = 53` — блок DNS IPv4
  6. `block out quick proto {udp tcp} from any to any port = 853` — блок DoT IPv4
  7. `block out quick inet6 proto {udp tcp} from any to any port = 53` — блок DNS IPv6
  8. `block out quick inet6 proto {udp tcp} from any to any port = 853` — блок DoT IPv6

### 1.2 Диагностика текущего состояния (`sudo pfctl -sr`)
Вывод показал что **anchor `com.apple/*` загружен**, наши кастомные правила **применились**,  
но присутствуют **конфликты** — см. раздел 2.

### 1.3 Диаграмма трафика
Построена draw.io диаграмма с горизонтальным вектором маршрута:



# в pf anchor — добавить ПЕРЕД block правилами:

pass out quick on en0 proto {udp tcp} to 9.9.9.9 port 443 keep state

или настроить split-exclude в ClearVPN конфиге

---

### ⚠ FP5 — utunN self-loop
**Проблема:** `ifconfig utunN: inet 172.18.0.1 --> 172.18.0.1`  
Remote endpoint совпадает с локальным IP → все пакеты возвращаются обратно, туннель "up" но транспорт сломан.  
**Фикс:** серверная проблема на стороне ClearVPN. Попробовать другой сервер / re-auth / переустановка профиля.

---

## 3. Текущее состояние

| Компонент                  | Статус | Примечание                     |
| -------------------------- | ------ | ------------------------------ |
| pf anchor загружен         | ✅      | LaunchDaemon работает          |
| DNS leak protection        | ✅      | port 53/853 заблокированы      |
| dnscrypt-proxy старт       | ✗      | FP1 — netprobe на :53          |
| dnscrypt bootstrap         | ⚠      | FP2 — bootstrap на :53         |
| ClearVPN bridge (IP)       | ✅      | IP определяется                |
| ClearVPN tunnel (интернет) | ✗      | FP3 + FP4 — DNS блокируется pf |
| utunN transport            | ⚠      | FP5 — self-loop (server-side)  |

---

## 4. Что нужно сделать агенту на ревью

- [ ] **Проверить** `dnscrypt-proxy.toml` — исправить `netprobe_address` и `bootstrap_resolvers`
- [ ] **Обновить** pf anchor скрипт — добавить динамический whitelist для VPN DNS (`172.18.x.x:53`)
- [ ] **Проверить** есть ли хук в LaunchDaemon или `network-monitor.sh` который обновляет pf правила при VPN connect/disconnect
- [ ] **Проверить** наличие `split-exclude` маршрутов или добавить `pass out on en0 to 9.9.9.9 port 443` как fallback до поднятия VPN
- [ ] **Тест сценарий:**
  1. Запуск системы → dnscrypt стартует? → `dig @127.0.0.1 example.com`
  2. Подключение ClearVPN → интернет есть? → `curl -I https://example.com`
  3. DNS leak test → `curl https://dnsleaktest.com/api/` → должен показать Quad9

---

## 5. Структура репозитория (релевантные файлы)

foxhole-macos/
├── setup.sh # главный инсталлятор
├── configs/
│ ├── dnscrypt-proxy.toml # ← FP1, FP2 здесь
│ └── pf/
│ └── com.hardening.dnsleak # ← FP3, FP4 здесь
├── launchdaemons/
│ ├── com.hardening.pf.dnsleak.plist
│ └── com.hardening.dnscrypt.plist
└── scripts/
├── proxy-toggle.sh # vpn_active() → utun check
└── network-monitor.sh # хук при смене сети

---

## 6. Окружение

- **OS:** macOS (Apple Silicon, M-series)
- **VPN:** ClearVPN — протокол cascade IKEv2 → WireGuard → QUIC → **Hysteria2** (единственный рабочий)
- **DNS resolver:** dnscrypt-proxy → Quad9 (DoH/DNSCrypt)
- **pf:** нативный macOS pf, anchor система
- **Интерфейсы:** `en0` (физический), `utunN` (ClearVPN, номер динамический), `lo0`
- **VPN subnet:** `172.18.0.0/30` (внутренняя ClearVPN)