#!/usr/bin/env python3
"""
traffic/benign_iot_generator.py — benign IoT telemetry over TLS.

Each device runs in its own network namespace with a unique source IP
(see configs/devices.yaml and scripts/topology.sh).

Usage (single device in its namespace):
  sudo ip netns exec sensor-01 python3 traffic/benign_iot_generator.py \
      --device-id sensor-01 --profile temperature_sensor \
      --server 10.0.2.10 --port 8883 --duration 600

Usage (all devices, from host):
  python3 traffic/benign_iot_generator.py --all --duration 600
"""
import ssl
import socket
import time
import random
import json
import threading
import logging
import argparse
import os

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("IoT-Gen")

PROFILES = {
    "temperature_sensor": {"interval_s": (10.0, 2.0), "payload_size": (48, 80),
                           "burst_probability": 0.02, "burst_count": (3, 8)},
    "smart_camera":       {"interval_s": (0.5, 0.1), "payload_size": (800, 1400),
                           "burst_probability": 0.10, "burst_count": (10, 50)},
    "smart_plug":         {"interval_s": (30.0, 5.0), "payload_size": (32, 64),
                           "burst_probability": 0.01, "burst_count": (2, 5)},
    "door_lock":          {"interval_s": (60.0, 10.0), "payload_size": (64, 128),
                           "burst_probability": 0.05, "burst_count": (3, 10)},
    "smart_thermostat":   {"interval_s": (15.0, 3.0), "payload_size": (96, 200),
                           "burst_probability": 0.03, "burst_count": (5, 15)},
}


def run_iot_device(device_id, profile_name, server_ip, server_port=8883,
                   duration_s=3600.0, result_holder=None):
    """Run a single IoT device, sending TLS telemetry.

    Args:
        result_holder: if provided, a dict; on return it will contain
            {"msg_count": int, "exceptions": list[str], "connections": int}.
            Used by the test suite to verify the F1 fix.
    """
    profile = PROFILES[profile_name]
    interval_mean, interval_std = profile["interval_s"]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    msg_count = 0
    connections = 0
    exceptions = []
    start = time.time()
    while time.time() - start < duration_s:
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(10)
            tls = ctx.wrap_socket(raw, server_hostname=server_ip)
            tls.connect((server_ip, server_port))
            connections += 1
            logger.info(f"[{device_id}] connected (conn #{connections})")

            while time.time() - start < duration_s:
                size = random.randint(*profile["payload_size"])
                payload = json.dumps({
                    "id": device_id, "type": profile_name,
                    "ts": time.time(), "seq": msg_count,
                    "data": "x" * max(0, size - 80),
                }).encode()[:size]
                if len(payload) < size:
                    payload += b"\x00" * (size - len(payload))
                tls.sendall(payload)
                msg_count += 1

                # Compute wait BEFORE logging it (F1 fix: 'wait' was used
                # before assignment, causing every connection to send only
                # one message then crash into the reconnect handler).
                wait = max(0.1, random.gauss(interval_mean, interval_std))

                logger.info(f"[{device_id:<12} | {profile_name:<18}] "
                            f"Telemetry #{msg_count:03d} sent ({len(payload):4d}B) "
                            f"-> next in ~{wait:.1f}s")

                if random.random() < profile["burst_probability"]:
                    for _ in range(random.randint(*profile["burst_count"])):
                        burst = bytes(random.getrandbits(8)
                                      for _ in range(random.randint(*profile["payload_size"])))
                        tls.sendall(burst)
                        time.sleep(random.uniform(0.01, 0.1))

                time.sleep(wait)
            tls.close()
        except Exception as e:
            exceptions.append(str(e))
            logger.warning(f"[{device_id}] connection error: {e}")
            time.sleep(5)

    logger.info(f"[{device_id}] done, sent {msg_count} messages in {connections} connection(s)")
    if result_holder is not None:
        result_holder["msg_count"] = msg_count
        result_holder["connections"] = connections
        result_holder["exceptions"] = exceptions


def load_devices(yaml_path=None):
    """Load device fleet from configs/devices.yaml."""
    if yaml_path is None:
        yaml_path = os.path.join(os.path.dirname(__file__), "..", "configs", "devices.yaml")
    try:
        import yaml
    except ImportError:
        # Fallback: use a safe subset of the default fleet
        logger.warning("PyYAML not installed; using built-in device list")
        return [
            {"device_id": "sensor-01", "profile": "temperature_sensor",
             "ip": "10.0.1.10", "class": "sensor"},
            {"device_id": "plug-01", "profile": "smart_plug",
             "ip": "10.0.1.20", "class": "plug"},
        ]
    yaml_path = os.path.abspath(yaml_path)
    with open(yaml_path) as f:
        cfg = yaml.safe_load(f)
    return cfg.get("devices", [])


def generate_benign_traffic(server_ip="10.0.2.10", server_port=8883,
                            duration_s=3600.0, devices=None):
    """Start all benign devices as threads (used in single-namespace mode or tests)."""
    if devices is None:
        devices = [
            ("iot-temp-01", "temperature_sensor"),
            ("iot-temp-02", "temperature_sensor"),
            ("iot-cam-01",  "smart_camera"),
            ("iot-plug-01", "smart_plug"),
            ("iot-plug-02", "smart_plug"),
            ("iot-lock-01", "door_lock"),
            ("iot-therm-01", "smart_thermostat"),
        ]
    threads = []
    for entry in devices:
        if isinstance(entry, dict):
            device_id = entry["device_id"]
            profile_name = entry["profile"]
        else:
            device_id, profile_name = entry
        t = threading.Thread(target=run_iot_device,
                             args=(device_id, profile_name, server_ip, server_port, duration_s))
        t.daemon = True
        t.start()
        threads.append(t)
        time.sleep(random.uniform(0.5, 3.0))
    logger.info(f"started {len(threads)} devices")
    for t in threads:
        t.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benign IoT traffic generator")
    parser.add_argument("--device-id", help="Single device ID to run")
    parser.add_argument("--profile", help="Profile name (for single device mode)")
    parser.add_argument("--server", default="10.0.2.10", help="Server IP")
    parser.add_argument("--port", type=int, default=8883, help="Server port")
    parser.add_argument("--duration", type=float, default=3600.0, help="Duration in seconds")
    parser.add_argument("--all", action="store_true",
                        help="Run all devices from configs/devices.yaml (legacy thread mode)")
    # Legacy positional argument: duration
    parser.add_argument("legacy_duration", nargs="?", type=float, default=None)
    args = parser.parse_args()

    duration = args.legacy_duration if args.legacy_duration else args.duration

    if args.device_id and args.profile:
        # Single-device mode (each device in its own namespace)
        run_iot_device(args.device_id, args.profile, args.server, args.port, duration)
    else:
        # Legacy all-in-one-namespace mode
        generate_benign_traffic(server_ip=args.server, server_port=args.port,
                                duration_s=duration)
