#!/usr/bin/env python3
import socket
import json
import os
import argparse
import dns.resolver
import idna

CONFIG_FILE = os.path.expanduser("~/.dns_analyzer_config.json")

def load_config():
    """Загружает конфигурацию из файла или возвращает значения по умолчанию."""
    default_config = {"dkim_selector": "dkim", "dmarc_selector": "_dmarc"}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = json.load(f)
            return {
                "dkim_selector": config.get("dkim_selector", default_config["dkim_selector"]),
                "dmarc_selector": config.get("dmarc_selector", default_config["dmarc_selector"])
            }
        except Exception as e:
            print(f"Ошибка загрузки конфигурации: {e}. Используются значения по умолчанию.")
    else:
        print(f"Конфигурационный файл {CONFIG_FILE} не найден. Используются значения по умолчанию.")
    return default_config

def create_resolver(dns_server):
    """Создаёт резолвер с указанным DNS-сервером или использует системный по умолчанию."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3
    if dns_server:
        try:
            resolver.nameservers = [socket.gethostbyname(dns_server.lstrip('@'))]
        except Exception as e:
            print(f"Ошибка: Неверный DNS-сервер {dns_server}: {e}. Используется системный DNS.")
    return resolver

def get_dns_records(domain, resolver, record_type):
    """Получает DNS-записи указанного типа для домена."""
    try:
        answers = resolver.resolve(domain, record_type, raise_on_no_answer=True)
        return [str(r).strip('"') for r in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return ["; no answer"]
    except Exception as e:
        return [f"; ERROR: {str(e)}"]

def main():
    parser = argparse.ArgumentParser(description="Консольный DNS-анализатор в формате dig")
    parser.add_argument("args", nargs='+', help="Домен, тип записи (A, MX, TXT и т.д.) или DNS-сервер (@server)")
    
    args = parser.parse_args()

    # Разделяем аргументы на домен, тип записи и DNS-сервер
    domain = None
    record_type = None
    dns_server = ""
    
    valid_record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    for arg in args.args:
        if arg.startswith('@'):
            dns_server = arg
        elif arg.upper() in valid_record_types:
            record_type = arg.upper()
        else:
            domain = arg

    if not domain:
        print("Ошибка: Домен не указан.")
        return

    # Преобразование кириллического домена в Punycode
    try:
        domain = idna.encode(domain).decode('ascii')
    except idna.IDNAError:
        domain = domain  # Если не IDN, оставляем как есть

    config = load_config()
    resolver = create_resolver(dns_server)

    # Определяем список записей для запроса
    if record_type:
        record_types = [(record_type, domain)]
        # Если указан TXT, добавляем DKIM и DMARC, если они соответствуют
        if record_type == 'TXT':
            record_types.append(('TXT', f"{config['dkim_selector']}._domainkey.{domain}"))
            record_types.append(('TXT', f"{config['dmarc_selector']}.{domain}"))
    else:
        record_types = [
            ('A', domain),
            ('AAAA', domain),
            ('MX', domain),
            ('NS', domain),
            ('TXT', domain),
            ('CNAME', domain),
            ('SOA', domain),
            ('TXT', f"{config['dkim_selector']}._domainkey.{domain}"),
            ('TXT', f"{config['dmarc_selector']}.{domain}")
        ]

    # Вывод в формате dig
    for rtype, query_domain in record_types:
        cmd = f"dig {dns_server + ' ' if dns_server else ''}{query_domain} {rtype} +short"
        values = get_dns_records(query_domain, resolver, rtype)
        print(cmd)
        print("\n".join(values))
        print()

if __name__ == "__main__":
    main()
