#!/usr/bin/env python3
import os
import sys
import logging
from pathlib import Path
from typing import Optional, List

# Власні модулі
import src.wifi.android
import src.wifi.scanner
import src.wps.connection
import src.wps.bruteforce
import src.utils
import src.args

# Налаштування логування
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("ose.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def validate_environment() -> None:
    """Перевірка середовища: версія Python, права root."""
    if sys.hexversion < 0x030800F0:
        src.utils.die("Потрібен Python 3.8 або новіший.")
    if os.getuid() != 0:
        src.utils.die("Запустіть скрипт з правами root.")

def setup_directories(*dirs: Path) -> None:
    """Створення необхідних директорій."""
    for directory in dirs:
        directory.mkdir(parents=True, exist_ok=True)
        logger.info(f"Директорія створена/перевірена: {directory}")

def handle_mtk_wifi() -> None:
    """Обробка MediaTek Wi-Fi інтерфейсу."""
    wmtWifi_device = Path('/dev/wmtWifi')
    if not wmtWifi_device.is_char_device():
        src.utils.die("Помилка MediaTek Wi-Fi: /dev/wmtWifi не знайдено або не є character device.")
    wmtWifi_device.chmod(0o644)
    wmtWifi_device.write_text('1', encoding='utf-8')
    logger.info("MediaTek Wi-Fi інтерфейс активовано.")

def main_loop(args) -> None:
    """Головний цикл обробки мереж."""
    android_network = src.wifi.android.AndroidNetwork()
    try:
        while True:
            if args.clear:
                src.utils.clearScreen()

            # Робота з Android
            if src.utils.isAndroid():
                android_network.storeAlwaysScanState()
                android_network.disableWifi()

            # Ініціалізація Bruteforce або звичайного підключення
            if args.bruteforce:
                connection = src.wps.bruteforce.Initialize(args.interface)
            else:
                connection = src.wps.connection.Initialize(
                    args.interface, args.write, args.save, args.verbose
                )

            # Обробка PBC або сканування мереж
            if args.pbc:
                connection.singleConnection(pbc_mode=True)
            else:
                if not args.bssid:
                    logger.info("BSSID не вказано — сканування мереж...")
                    vuln_list = _load_vulnerable_networks(args.vuln_list)
                    scanner = src.wifi.scanner.WiFiScanner(args.interface, vuln_list)
                    args.bssid = scanner.promptNetwork()

                if args.bssid:
                    if args.bruteforce:
                        connection.smartBruteforce(args.bssid, args.pin, args.delay)
                    else:
                        connection.singleConnection(
                            args.bssid, args.pin, args.pixie_dust,
                            args.show_pixie_cmd, args.pixie_force
                        )

            if not args.loop:
                break
            args.bssid = None  # Скидання BSSID для нового циклу

    except KeyboardInterrupt:
        logger.info("\nПереривання користувачем.")
        if args.loop and input("\n[?] Вийти? (Y/n): ").lower() == 'y':
            raise SystemExit("Скрипт завершено.")
    finally:
        if src.utils.isAndroid():
            android_network.enableWifi()

def _load_vulnerable_networks(vuln_list_path: str) -> List[str]:
    """Завантаження списку вразливих мереж з файлу."""
    try:
        with open(vuln_list_path, 'r', encoding='utf-8') as file:
            return file.read().splitlines()
    except FileNotFoundError:
        logger.warning(f"Файл {vuln_list_path} не знайдено.")
        return []

if __name__ == '__main__':
    validate_environment()
    args = src.args.parseArgs()

    # Ініціалізація директорій
    setup_directories(
        Path(src.utils.SESSIONS_DIR),
        Path(src.utils.PIXIEWPS_DIR)
    )

    # Обробка MediaTek Wi-Fi
    if args.mtk_wifi:
        handle_mtk_wifi()

    # Керування мережевим інтерфейсом
    if not src.utils.ifaceCtl(args.interface, action='up'):
        src.utils.die(f"Не вдалося активувати інтерфейс {args.interface}")

    # Головний цикл
    try:
        main_loop(args)
    finally:
        # Завершальні дії
        if args.iface_down:
            src.utils.ifaceCtl(args.interface, action='down')
        if args.mtk_wifi:
            Path('/dev/wmtWifi').write_text('0', encoding='utf-8')
            logger.info("MediaTek Wi-Fi інтерфейс деактивовано.")