# MailHunter environment bootstrap
# This file is intentionally kept as a standalone setup script.

import os
import subprocess
import sys
from pathlib import Path


def create_directory_structure():
    """Create project directory structure."""
    directories = [
        'core',
        'security',
        'integrations',
        'gui',
        'utils',
        'data',
        'data/blacklists',
        'data/whitelists',
        'data/rules',
        'data/templates',
        'data/quarantine',
        'data/export',
        'tests',
        'scripts',
        'logs',
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        if directory in ['core', 'security', 'integrations', 'gui', 'utils', 'tests']:
            init_file = Path(directory) / '__init__.py'
            init_file.touch(exist_ok=True)


def install_dependencies():
    """Install Python dependencies."""
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        return True
    except subprocess.CalledProcessError:
        return False


def create_default_blacklists():
    """Create default blacklist files."""
    suspicious_domains = ['example-phishing.com', 'fake-bank.tk', 'suspicious-site.ml']
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']

    Path('data/blacklists').mkdir(parents=True, exist_ok=True)
    (Path('data/blacklists') / 'domains.txt').write_text('\n'.join(suspicious_domains), encoding='utf-8')
    (Path('data/blacklists') / 'tlds.txt').write_text('\n'.join(suspicious_tlds), encoding='utf-8')


def create_readme():
    """Create a basic README.md."""
    readme_content = """# MailHunter

Advanced email security tool.

## Installation

```bash
python setup_env.py
```

## Run

```bash
python mailhunter_cli.py
```
"""
    Path('README.md').write_text(readme_content, encoding='utf-8')


def create_gitignore():
    """Create a basic .gitignore."""
    gitignore_content = """# MailHunter .gitignore

config.ini
mailhunter.key
*.key
*.db
*.sqlite
*.sqlite3
logs/
*.log
__pycache__/
*.py[cod]
venv/
.env
"""
    Path('.gitignore').write_text(gitignore_content, encoding='utf-8')


def main():
    print('=' * 60)
    print('MailHunter - Setup Environment')
    print('=' * 60)

    if sys.version_info < (3, 8):
        print('Python 3.8 or newer is required.')
        sys.exit(1)

    create_directory_structure()
    if not install_dependencies():
        print('Dependency installation failed. Run: pip install -r requirements.txt')

    create_default_blacklists()
    create_readme()
    create_gitignore()

    print('Setup complete.')


if __name__ == '__main__':
    main()
