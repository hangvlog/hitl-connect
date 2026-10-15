"""Opt-in current-user login launcher for an existing system-SSH provider.

Install beside startup-config.json. Uses normal ShellExecute runas; never changes
UAC, execution policy, service startup, accounts, keys or connection codes.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def emit(root, event, **fields):
    path = root / "startup.log"
    if path.exists() and path.stat().st_size > 262144:
        path.replace(root / "startup.previous.log")
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                                 "event": event, **fields}) + "\n")


def validate(config):
    for key in ("provider", "cli"):
        path = Path(config[key])
        if not path.is_absolute() or not path.is_file():
            raise ValueError("missing_binary")
        if hashlib.sha256(path.read_bytes()).hexdigest() != config[key + "Sha256"]:
            raise ValueError("binary_hash_mismatch")
    profile = Path(config["profile"])
    if not profile.is_absolute() or not profile.is_dir():
        raise ValueError("missing_profile")
    if config["uiAddress"] != "127.0.0.1:59369":
        raise ValueError("unexpected_panel_address")


def agent(config, action="status"):
    process = subprocess.run(
        [config["cli"], "agent", action, "--dir", config["profile"]],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=40, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    # Do not write command output, session tokens or profile contents to logs.
    return json.loads(process.stdout.decode("utf-8"))


def elevate(config):
    args = subprocess.list2cmdline([
        "system-ssh-host", "--dir", config["profile"],
        "--ui-address", config["uiAddress"],
    ])
    call = ctypes.WinDLL("shell32", use_last_error=True).ShellExecuteW
    call.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                     ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int]
    call.restype = ctypes.c_void_p
    result = call(None, "runas", config["provider"], args,
                  str(Path(config["provider"]).parent), 0)
    if not result or result <= 32:
        return int(result or 0)
    return 0


def ensure_provider(config, log, query=agent, launch=elevate, sleep=time.sleep):
    current = query(config)
    state = current.get("state") or {}
    if state.get("running"):
        log("already_running")
        return 0
    # An available panel that the user stopped must remain stopped.
    if current.get("code") != "SYSTEM_SSH_PROVIDER_NOT_RUNNING":
        log("not_started", code=current.get("code", "UNKNOWN"))
        return 1
    error = launch(config)
    if error:
        log("elevation_not_completed", nativeCode=error)
        return 1
    log("launch_requested")
    for _ in range(20):
        sleep(2)
        result = query(config)
        state = result.get("state") or {}
        if state.get("running"):
            # This is process readiness, never proof of a remote SSH login.
            log("provider_running")
            return 0
        if state.get("configured") and result.get("code") != "SYSTEM_SSH_PROVIDER_NOT_RUNNING":
            log("provider_stopped_or_failed", code=result.get("code", "UNKNOWN"))
            return 1
    log("startup_not_confirmed")
    return 1


def main():
    root = Path(__file__).resolve().parent
    if os.name != "nt":
        return 1
    emit(root, "launcher_entered")
    import msvcrt
    with (root / ".startup.lock").open("a+b") as lock:
        lock.seek(0, 2)
        if lock.tell() == 0:
            lock.write(b"0")
            lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return 0
        try:
            config = json.loads((root / "startup-config.json").read_text(encoding="utf-8-sig"))
            validate(config)
            return ensure_provider(config, lambda event, **fields: emit(root, event, **fields))
        except Exception as error:
            # Exception type only: paths and subprocess output can be sensitive.
            emit(root, "startup_failed", errorType=type(error).__name__)
            return 1
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


if __name__ == "__main__":
    raise SystemExit(main())
