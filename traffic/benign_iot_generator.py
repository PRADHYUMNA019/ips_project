#!/usr/bin/env python3
"""
traffic/benign_iot_generator.py — benign IoT telemetry over TLS.

Each device runs in its own network namespace with a unique source IP
(see configs/devices.yaml and scripts/topology.sh).

Usage (single device from config):
  sudo ip netns exec sensor-01 python3 traffic/benign_iot_generator.py \
      --device-from-config sensor-01 --duration 600

Usage (explicit parameters):
  sudo ip netns exec sensor-01 python3 traffic/benign_iot_generator.py \
      --device-id sensor-01 --profile temperature_sensor --connection persistent \
      --server 10.0.2.10 --port 8883 --duration 600 --time-scale 1.0

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
    "temperature_sensor": {
        "interval_s": (10.0, 2.0),
        "payload_size": (48, 80),
        "burst_probability": 0.02,
        "burst_count": (3, 8),
        "reconnect_after_msgs": (40, 80),
    },
    "smart_camera": {
        "interval_s": (0.5, 0.1),
        "payload_size": (800, 1400),
        "burst_probability": 0.10,
        "burst_count": (10, 50),
        "reconnect_after_msgs": (100, 300),
    },
    "smart_plug": {
        "interval_s": (30.0, 5.0),
        "payload_size": (32, 64),
        "burst_probability": 0.01,
        "burst_count": (2, 5),
        "reconnect_after_msgs": (30, 60),
    },
    "door_lock": {
        "interval_s": (60.0, 10.0),
        "payload_size": (64, 128),
        "burst_probability": 0.05,
        "burst_count": (3, 10),
        "reconnect_after_msgs": (20, 50),
    },
    "smart_thermostat": {
        "interval_s": (15.0, 3.0),
        "payload_size": (96, 200),
        "burst_probability": 0.03,
        "burst_count": (5, 15),
        "reconnect_after_msgs": (30, 70),
    },
}


def load_devices(yaml_path=None):
    """Load device fleet from configs/devices.yaml."""
    if yaml_path is None:
        yaml_path = os.path.join(os.path.dirname(__file__), "..", "configs", "devices.yaml")
    try:
        import yaml
    except ImportError:
        logger.warning("PyYAML not installed; using built-in fallback device list")
        return [
            {"device_id": "sensor-01", "profile": "temperature_sensor",
             "ip": "10.0.1.10", "class": "sensor", "connection": "persistent"},
            {"device_id": "plug-01", "profile": "smart_plug",
             "ip": "10.0.1.20", "class": "plug", "connection": "persistent"},
        ]
    yaml_path = os.path.abspath(yaml_path)
    with open(yaml_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return cfg.get("devices", [])


def get_device_config(device_id, yaml_path=None):
    """Look up a single device by ID in configs/devices.yaml."""
    devices = load_devices(yaml_path)
    for dev in devices:
        if dev.get("device_id") == device_id:
            return dev
    return None


def run_iot_device(device_id, profile_name, server_ip, server_port=8883,
                   duration_s=3600.0, result_holder=None,
                   connection_type="persistent", time_scale=1.0):
    """Run a single IoT device, sending TLS telemetry.

    Args:
        device_id: Identifier of the device.
        profile_name: Key in PROFILES dict.
        server_ip: Target TLS server IP.
        server_port: Target TLS server port.
        duration_s: How long to run in seconds.
        result_holder: If provided, a dict populated on return:
            {"msg_count": int, "connections": int, "exceptions": list[str]}.
        connection_type: "persistent" (keep-alive with periodic reconnects)
                         or "reconnect" (new TLS connection per message).
        time_scale: Multiplier for timing intervals (e.g. 0.1 for 10x faster).
    """
    profile = PROFILES[profile_name]
    raw_mean, raw_std = profile["interval_s"]
    interval_mean = max(0.01, raw_mean * time_scale)
    interval_std = max(0.005, raw_std * time_scale)

    reconnect_range = profile.get("reconnect_after_msgs", (50, 100))

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
            logger.info(f"[{device_id}] connected (conn #{connections}, mode={connection_type})")

            # Determine reconnect limit for persistent mode
            if connection_type == "reconnect":
                max_msgs_this_conn = 1
            else:
                max_msgs_this_conn = random.randint(*reconnect_range)

            msgs_in_conn = 0
            while time.time() - start < duration_s and msgs_in_conn < max_msgs_this_conn:
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
                msgs_in_conn += 1

                # Wait computed before logging (F1 fix)
                wait = max(0.02, random.gauss(interval_mean, interval_std))
                logger.info(f"[{device_id:<12} | {profile_name:<18}] "
                            f"Telemetry #{msg_count:03d} ({len(payload):4d}B) "
                            f"[conn #{connections}: msg {msgs_in_conn}/{max_msgs_this_conn}] "
                            f"-> next in ~{wait:.2f}s")

                # Bursts if configured
                if random.random() < profile.get("burst_probability", 0.0):
                    burst_cnt = random.randint(*profile.get("burst_count", (1, 3)))
                    for _ in range(burst_cnt):
                        b_size = random.randint(*profile["payload_size"])
                        burst = bytes(random.getrandbits(8) for _ in range(b_size))
                        tls.sendall(burst)
                        time.sleep(random.uniform(0.005, 0.05) * time_scale)

                if time.time() - start < duration_s:
                    time.sleep(wait)

            try:
                tls.close()
            except Exception:
                pass

        except Exception as e:
            exceptions.append(str(e))
            logger.warning(f"[{device_id}] connection error: {e}")
            time.sleep(max(0.5, 2.0 * time_scale))

    logger.info(f"[{device_id}] done, sent {msg_count} messages in {connections} connection(s)")
    if result_holder is not None:
        result_holder["msg_count"] = msg_count
        result_holder["connections"] = connections
        result_holder["exceptions"] = exceptions


def generate_benign_traffic(server_ip="10.0.2.10", server_port=8883,
                            duration_s=3600.0, devices=None, time_scale=1.0):
    """Start all benign devices as threads."""
    if devices is None:
        devices = load_devices()

    threads = []
    for entry in devices:
        if isinstance(entry, dict):
            device_id = entry["device_id"]
            profile_name = entry["profile"]
            conn_type = entry.get("connection", "persistent")
        else:
            device_id, profile_name = entry
            conn_type = "persistent"

        t = threading.Thread(
            target=run_iot_device,
            args=(device_id, profile_name, server_ip, server_port),
            kwargs={
                "duration_s": duration_s,
                "connection_type": conn_type,
                "time_scale": time_scale,
            },
        )
        t.daemon = True
        t.start()
        threads.append(t)
        time.sleep(random.uniform(0.1, 0.5) * time_scale)

    logger.info(f"Started {len(threads)} devices")
    for t in threads:
        t.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Benign IoT traffic generator")
    parser.add_argument("--device-id", help="Single device ID to run")
    parser.add_argument("--profile", help="Profile name (for single device mode)")
    parser.add_argument("--connection", choices=["persistent", "reconnect"], default="persistent",
                        help="Connection style: persistent (keep-alive) or reconnect (new conn per msg)")
    parser.add_argument("--device-from-config", help="Load device ID profile & connection from devices.yaml")
    parser.add_argument("--server", default="10.0.2.10", help="Server IP")
    parser.add_argument("--port", type=int, default=8883, help="Server port")
    parser.add_argument("--duration", type=float, default=3600.0, help="Duration in seconds")
    parser.add_argument("--time-scale", type=float, default=1.0,
                        help="Scale timing intervals (e.g. 0.1 for 10x faster collection)")
    parser.add_argument("--all", action="store_true",
                        help="Run all devices from configs/devices.yaml as threads")
    parser.add_argument("legacy_duration", nargs="?", type=float, default=None)
    args = parser.parse_args()

    duration = args.legacy_duration if args.legacy_duration else args.duration

    if args.device_from_config:
        cfg = get_device_config(args.device_from_config)
        if not cfg:
            logger.error(f"Device '{args.device_from_config}' not found in configs/devices.yaml")
            exit(1)
        run_iot_device(
            device_id=cfg["device_id"],
            profile_name=cfg["profile"],
            server_ip=args.server,
            server_port=args.port,
            duration_s=duration,
            connection_type=cfg.get("connection", "persistent"),
            time_scale=args.time_scale,
        )
    elif args.device_id and args.profile:
        run_iot_device(
            device_id=args.device_id,
            profile_name=args.profile,
            server_ip=args.server,
            server_port=args.port,
            duration_s=duration,
            connection_type=args.connection,
            time_scale=args.time_scale,
        )
    else:
        generate_benign_traffic(
            server_ip=args.server,
            server_port=args.port,
            duration_s=duration,
            time_scale=args.time_scale,
        )
