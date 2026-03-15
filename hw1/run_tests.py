import subprocess
import sys
import time
import os

PROTOCOLS = ["tcp", "udp", "quic"]
#PROTOCOLS = ["quic"]
BLOCK_SIZES = [60000//5*i for i in range(1, 6)]
DATA_SIZES_MB = [512, 1024]
MODES = ["streaming", "stop-and-wait"]
HOST = "127.0.0.1"
BASE_PORT = 13000

TIMEOUT_PER_TEST = 7200
RESULTS_FILE = "results.txt"

LOG_FILE = None


def start_server(protocol, port):
    return subprocess.Popen(
        [sys.executable, "server.py", "--protocol", protocol,
         "--host", HOST, "--port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def run_client(protocol, port, size_mb, block_size, mode):
    return subprocess.run(
        [sys.executable, "client.py", "--protocol", protocol,
         "--host", HOST, "--port", str(port),
         "--size", str(size_mb), "--block-size", str(block_size),
         "--mode", mode],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_PER_TEST,
    )


def kill_server(proc):
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def log(msg):
    print(msg, flush=True)
    if LOG_FILE:
        LOG_FILE.write(msg + "\n")
        LOG_FILE.flush()


def main():
    global LOG_FILE
    port = BASE_PORT
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    LOG_FILE = open(RESULTS_FILE, "w", encoding="utf-8")

    for protocol in PROTOCOLS:
        for mode in MODES:
            if protocol == "tcp" and mode == "stop-and-wait":
                continue

            for block_size in BLOCK_SIZES:
                for data_mb in DATA_SIZES_MB:
                    port += 1
                    label = (
                        f"{protocol.upper()} | {mode} | "
                        f"{data_mb} MB | block={block_size}"
                    )
                    log(f"\n{'='*60}")
                    log(f"TEST: {label}")
                    log(f"{'='*60}")

                    server = start_server(protocol, port)
                    time.sleep(2 if protocol != "quic" else 3)

                    try:
                        result = run_client(
                            protocol, port, data_mb, block_size, mode
                        )
                        if result.stdout:
                            log(result.stdout.strip())
                        if result.returncode != 0:
                            log(f"CLIENT FAILED (rc={result.returncode})")
                            if result.stderr:
                                log(result.stderr.strip())
                    except subprocess.TimeoutExpired:
                        log(f"TIMEOUT after {TIMEOUT_PER_TEST}s - skipping")
                    finally:
                        kill_server(server)

    log("\nAll tests completed.")
    LOG_FILE.close()


if __name__ == "__main__":
    main()
