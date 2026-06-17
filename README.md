# Round Table Encrypted Chat

Групповой чат с шифрованием и TUI интерфейсом. Топология "звезда".

## Установка
```bash
pip install -r requirements.txt
```

## Использование

**Сервер:**
```bash
# Сгенерировать TLS сертификаты вручную
python -m core.tls --generate --host my-server.local

# Простой сервер (TCP, без пароля, без E2E)
python chat.py --host 127.0.0.1 --port 8888 --nick Alice

# Сервер с полным фаршем (TLS + пароль + E2E)
python chat.py --host 127.0.0.1 --port 8888 --nick Alice --tls --password secret123 --e2e
```

**Клиенты:**
```bash
python chat.py --host 127.0.0.1 --port 8889 --peer 127.0.0.1:8888 --nick Bob --tls --password secret123 --e2e
```

## Команды в чате
- `/nick <name>` — сменить ник
- `/users` — список пользователей онлайн
- `/clear` — очистить историю
- `/quit` или `/exit` — выйти
