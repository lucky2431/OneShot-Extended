import sys
import os
import pathlib
import subprocess
import shutil
from pathlib import Path

# Константи
USER_HOME = str(pathlib.Path.home())
SESSIONS_DIR = f'{USER_HOME}/.OneShot-Extended/sessions/'
PIXIEWPS_DIR = f'{USER_HOME}/.OneShot-Extended/pixiewps/'
REPORTS_DIR = f'{os.getcwd()}/reports/'

def isAndroid():
    """Check if this project is ran on android."""
    return bool(hasattr(sys, 'getandroidapilevel'))

def _rfkill_unblock():
    """Unblock wifi with rfkill."""
    rfkill_command = ['rfkill', 'unblock', 'wifi']
    return subprocess.run(rfkill_command, check=False)

def _iface_ctl(interface: str, action: str):
    """Internal function to handle interface control with common logic."""
    command = ['ip', 'link', 'set', f'{interface}', f'{action}']
    command_output = subprocess.run(
        command, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    command_output_stripped = command_output.stdout.strip()
    
    # Fix "RNETLINK: No such device" issues on specific android devices
    if isAndroid() is False and 'RF-kill' in command_output_stripped:
        print('[!] RF-kill is blocking the interface, unblocking')
        _rfkill_unblock()
        # Retry the command after unblocking
        command_output = subprocess.run(
            command, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        command_output_stripped = command_output.stdout.strip()
    
    if command_output.returncode != 0:
        print(f'[!] {command_output_stripped}')
    
    return command_output.returncode

def iface_up(iface: str) -> bool:
    """Bring interface up."""
    return _iface_ctl(iface, 'up') == 0

def iface_down(iface: str) -> bool:
    """Bring interface down."""
    return _iface_ctl(iface, 'down') == 0

def ifaceCtl(interface: str, action: str):
    """Legacy function - put an interface up or down."""
    return _iface_ctl(interface, action)

def clearScreen():
    """Clear the terminal screen."""
    os.system('clear')

def die(text: str):
    """Print an error and exit with non-zero exit code."""
    sys.exit(f'[!] {text} \n')

def migrate_and_create_dirs():
    """Migrate from old directory structure and create necessary directories."""
    old = Path("~/OSE").expanduser()
    new = Path("~/.OneShot-Extended").expanduser()
    
    if old.exists() and old.is_dir():
        try:
            shutil.move(str(old), str(new))
            print("[+] Міграція старих даних виконана")
        except Exception as e:
            print(f"[!] Не вдалося мігрувати дані: {e}")
    
    # Create necessary directories
    for d in [SESSIONS_DIR, PIXIEWPS_DIR, REPORTS_DIR]:
        Path(d).mkdir(parents=True, exist_ok=True)

# Додаткові утиліти
def check_dependencies():
    """Check if required tools are available."""
    required_tools = ['ip', 'iw', 'aircrack-ng']
    missing = []
    
    for tool in required_tools:
        if shutil.which(tool) is None:
            missing.append(tool)
    
    if missing:
        die(f"Відсутні необхідні інструменти: {', '.join(missing)}")

def get_interface_mode(interface: str) -> str:
    """Get current interface mode."""
    try:
        result = subprocess.run(
            ['iw', 'dev', interface, 'info'],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.split('\n'):
            if 'type' in line:
                return line.split('type')[-1].strip()
    except subprocess.CalledProcessError:
        pass
    return "unknown"