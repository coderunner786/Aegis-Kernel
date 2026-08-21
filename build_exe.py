import os
import sys
import psutil
import PyInstaller.__main__


def ensure_output_is_not_running(output_path):
    output_path = os.path.normcase(os.path.abspath(output_path))
    running_processes = []

    for process in psutil.process_iter(["pid", "name", "exe"]):
        try:
            process_path = process.info.get("exe")
            if process_path and os.path.normcase(os.path.abspath(process_path)) == output_path:
                running_processes.append(f"{process.info['name']} (PID {process.info['pid']})")
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            continue

    if running_processes:
        processes = ", ".join(running_processes)
        raise RuntimeError(
            f"Cannot rebuild because {processes} is running and locking {output_path}. "
            "Stop the running Aegis-Guard process, then run this command again."
        )


def build():
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)
    public_key_path = os.path.join(project_root, ".aegis_pubkey.pem")
    dashboard_path = os.path.join(project_root, "dashboard.html")
    vis_network_path = os.path.join(project_root, "vis-network.min.js")
    output_path = os.path.join(project_root, "dist", "Aegis-Guard.exe")

    for required_path, description in (
        (public_key_path, "Public verification key"),
        (dashboard_path, "Dashboard HTML"),
        (vis_network_path, "Offline dashboard library"),
    ):
        if not os.path.isfile(required_path):
            raise FileNotFoundError(f"{description} is missing: {required_path}")
    ensure_output_is_not_running(output_path)

    # On Windows, PyInstaller expects 'source_file;destination_folder'
    data_separator = ";" if os.name == "nt" else ":"

    # Base flags
    args = [
        os.path.join(project_root, "aegis_main.py"),
        "--name=Aegis-Guard",
        "--onefile",
        "--clean",
        "--noconfirm",
        "--collect-submodules=sklearn",
        f"--add-data={dashboard_path}{data_separator}.",
        f"--add-data={public_key_path}{data_separator}.",
        f"--distpath={os.path.join(project_root, 'dist')}",
        f"--workpath={os.path.join(project_root, 'build')}",
        f"--specpath={project_root}",
        f"--add-data={vis_network_path}{data_separator}.",
    ]

    # Include models folder if it exists in root
    if os.path.isdir("models"):
        args.append(f"--add-data={os.path.join(project_root, 'models')}{data_separator}models")

    # Include tests folder if it exists in root
    if os.path.isdir("tests"):
        args.append(f"--add-data={os.path.join(project_root, 'tests')}{data_separator}tests")

    print("[*] Starting PyInstaller compilation with bundled SOC dashboard...")
    PyInstaller.__main__.run(args)
    print("\n[✓] Build completed successfully: dist/Aegis-Guard.exe")


if __name__ == "__main__":
    build()