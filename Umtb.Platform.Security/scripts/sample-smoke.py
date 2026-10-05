"""Run the compiled sample under a specific dotnet host and check the HTTP boundary."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def request(url, token=None, method="GET"):
    headers = {"Authorization": "Bearer " + token} if token else {}
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers, method=method), timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def wait_ready(url, process=None, attempts=60):
    for _ in range(attempts):
        if process and process.poll() is not None:
            raise RuntimeError("Sample exited before becoming ready; inspect its log.")
        try:
            if request(url)[0] == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise RuntimeError("Service did not become ready: " + url)


def start_sample(framework, dotnet="dotnet", authority=None, environment=None):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = os.environ.copy()
    env["ASPNETCORE_ENVIRONMENT"] = environment or ("Development" if authority else "Production")
    if authority:
        env["Security__Authority"] = authority
        env["Security__AllowHttpDiscoveryInDevelopment"] = "true"
    directory = ROOT / "samples/Umtb.Platform.Security.Sample"
    dll = directory / "bin/Release" / framework / "Umtb.Platform.Security.Sample.dll"
    (ROOT / "artifacts").mkdir(exist_ok=True)
    log = (ROOT / "artifacts" / ("sample-" + framework + ".log")).open("w", encoding="utf-8")
    process = subprocess.Popen([dotnet, str(dll), "--urls", f"http://127.0.0.1:{port}"],
                               cwd=directory, env=env, stdout=log, stderr=subprocess.STDOUT)
    return process, log, f"http://127.0.0.1:{port}"


def stop_sample(process, log):
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--framework", default="net10.0")
    parser.add_argument("--dotnet", default="dotnet")
    parser.add_argument("--environment", choices=["Production", "Development", "Test", "Staging"], default="Production")
    args = parser.parse_args()
    proc, output, base = start_sample(args.framework, args.dotnet, environment=args.environment)
    try:
        wait_ready(base + "/health", proc)
        assert json.loads(request(base + "/health")[1])["status"] == "ok"
        for path in ["/", "/scalar.js", "/scalar.aspnetcore.js", "/openapi/v1.json"]:
            status, body = request(base + path)
            assert status == 200 and body, path
        document = json.loads(request(base + "/openapi/v1.json")[1])
        assert "/me" in document["paths"]
        assert document["components"]["securitySchemes"]["Keycloak"]["type"] == "oauth2"
        if args.environment != "Development":
            assert "fixture-password" not in document["info"]["description"]
        for path in ["/me", "/controller/orders", "/reports/daily"]:
            assert request(base + path)[0] == 401, path
        print("Sample startup, public Scalar documentation, health, and bearer challenges passed on " + args.framework + " (" + args.environment + ")")
    finally:
        stop_sample(proc, output)
