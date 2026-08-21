import PyInstaller.__main__
import importlib.util
from pathlib import Path

def build():
    print("[*] Starting Aegis standalone executable compilation...")

    project_root = Path(__file__).resolve().parent
    model_path = project_root / "models/isolation_forest.pkl"
    sig_path = project_root / "models/isolation_forest.pkl.sig"
    pubkey_path = project_root / ".aegis_pubkey.pem"

    # Verify build prerequisites
    if not model_path.exists() or not sig_path.exists():
        raise FileNotFoundError(
            "Signed model is missing. Run train_model.py on the trusted build machine first."
        )

    if not pubkey_path.exists():
        raise FileNotFoundError(
            "Public verification key is missing. Generate signing material on the trusted build machine first."
        )

    # Data bundle mapping (source;destination on Windows)
    datas = [
        f"{model_path};models",
        f"{sig_path};models",
        f"{pubkey_path};.",
        f"{project_root / 'tests'};tests",
    ]

    # Explicit hidden imports for dynamic libraries
    hidden_imports = [
        'cryptography',
        'sklearn',
        'sklearn.ensemble',
        'sklearn.tree',
        'sklearn.neighbors',
        'pydantic',
        'rich',
        'rich.console',
        'rich.panel',
        'rich.table',
        'sqlite3'
    ]
    if importlib.util.find_spec('wmi'):
        hidden_imports.extend(['wmi', 'win32com', 'win32com.client', 'pythoncom'])
    if importlib.util.find_spec('psutil'):
        hidden_imports.append('psutil')

    args = [
        str(project_root / 'aegis_main.py'),
        '--name=Aegis-Guard',
        '--onefile',
        '--console',
        '--clean',
        f'--distpath={project_root / "dist"}',
        f'--workpath={project_root / "build"}',
        f'--specpath={project_root}',
    ]

    for d in datas:
        args.append(f'--add-data={d}')

    for imp in hidden_imports:
        args.append(f'--hidden-import={imp}')

    PyInstaller.__main__.run(args)
    print("\n[✓] Aegis standalone executable built successfully!")
    print(r"[✓] Executable output location: dist\Aegis-Guard.exe")

if __name__ == "__main__":
    build()