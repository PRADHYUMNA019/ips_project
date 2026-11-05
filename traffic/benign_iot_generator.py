#!/usr/bin/env python3
"""
traffic/benign_iot_generator.py — Benign IoT telemetry over real MQTT-TLS and HTTPS (A5).

Modes:
  - Default (real protocol mode, A5):
      * Sensors, plugs, thermostats: publish via paho-mqtt over TLS (port 8883) to mosquitto.
      * Cameras: send HTTP/1.1 POST /upload requests of 20-200 KB over TLS (port 443/8443) to https_server.py.
      * Per-class TLS settings: plugs & thermostats pin TLS 1.2; sensors & cameras negotiate TLS 1.3/1.2.
  - Legacy raw-TLS echo mode (--legacy-echo):
      * Sends raw JSON frames over TLS socket for backward-compatible echo testing.
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

try:
    import paho.mqtt.client as mqtt
except Exception:
    mqtt = None

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("IoT-Gen")

PROFILES = {
    "temperature_sensor": {
        "interval_s": (10.0, 2.0),
        "payload_size": (48, 80),
        "burst_probability": 0.02,
        "burst_count": (3, 8),
        "reconnect_after_msgs": (40, 80),
        "protocol": "mqtt",
        "tls_version": "tls13",
    },
    "smart_camera": {
        "interval_s": (0.5, 0.1),
        "payload_size": (20480, 204800),  # A5: 20-200 KB HTTPS POST uploads
        "legacy_payload_size": (800, 1400),
        "burst_probability": 0.10,
        "burst_count": (3, 10),
        "reconnect_after_msgs": (20, 60),
        "protocol": "https",
        "tls_version": "tls13",
    },
    "smart_plug": {
        "interval_s": (30.0, 5.0),
        "payload_size": (32, 64),
        "burst_probability": 0.01,
        "burst_count": (2, 5),
        "reconnect_after_msgs": (30, 60),
        "protocol": "mqtt",
        "tls_version": "tls12",
    },
    "door_lock": {
        "interval_s": (60.0, 10.0),
        "payload_size": (64, 128),
        "burst_probability": 0.05,
        "burst_count": (3, 10),
        "reconnect_after_msgs": (20, 50),
        "protocol": "mqtt",
        "tls_version": "tls12",
    },
    "smart_thermostat": {
        "interval_s": (15.0, 3.0),
        "payload_size": (96, 200),
        "burst_probability": 0.03,
        "burst_count": (5, 15),
        "reconnect_after_msgs": (30, 70),
        "protocol": "mqtt",
        "tls_version": "tls12",
    },
}


def build_tls_context(profile_name: str) -> ssl.SSLContext:
    """Create SSLContext with per-class TLS version preferences (A5)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    prof = PROFILES.get(profile_name, {})
    tls_pref = prof.get("tls_version", "tls13")
    if hasattr(ssl, "TLSVersion"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if tls_pref == "tls12":
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def load_devices(yaml_path=None):
    """Load device fleet from configs/devices.yaml."""
    if yaml_path is None:
        yaml_path = os.path.join(os.path.dirname(__file__), "..", "configs", "devices.yaml")
    try:
        import yaml
    except ImportError:
        return [
            {"device_id": "sensor-01", "profile": "temperature_sensor",
             "ip": "10.0.1.11", "class": "sensor", "connection": "persistent"},
            {"device_id": "plug-01", "profile": "smart_plug",
             "ip": "10.0.1.21", "class": "plug", "connection": "persistent"},
        ]
    yaml_path = os.path.abspath(yaml_path)
    with open(yaml_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return cfg.get("devices", [])


def get_device_config(device_id, yaml_path=None):
    """Look up a single device by ID in configs/devices.yaml."""
    for dev in load_devices(yaml_path):
        if dev.get("device_id") == device_id:
            return dev
    return None


def _make_payload(device_id: str, profile_name: str, msg_count: int, size: int) -> bytes:
    header = json.dumps({
        "id": device_id,
        "type": profile_name,
        "ts": round(time.time(), 3),
        "seq": msg_count,
    }).encode("utf-8")
    if len(header) >= size:
        return header[:size]
    return header + (b"x" * (size - len(header)))


def run_iot_device(
    device_id,
    profile_name,
    server_ip,
    server_port=8883,
    duration_s=3600.0,
    result_holder=None,
    connection_type="persistent",
    time_scale=1.0,
    legacy_echo=None,
    protocol=None,
):
    """Run a single IoT device over MQTT-TLS, HTTPS, or legacy TLS echo."""
    profile = PROFILES[profile_name]
    raw_mean, raw_std = profile["interval_s"]
    interval_mean = max(0.01, raw_mean * time_scale)
    interval_std = max(0.005, raw_std * time_scale)
    reconnect_range = profile.get("reconnect_after_msgs", (50, 100))

    # Determine operating protocol
    if legacy_echo is None:
        # Synthetic unit-test profiles (_test_*) default to legacy echo unless protocol is specified
        legacy_echo = bool(profile_name.startswith("_test_") and protocol is None)

    if legacy_echo:
        active_proto = "legacy_echo"
    else:
        active_proto = protocol or profile.get("protocol", "mqtt")

    ctx = build_tls_context(profile_name)
    msg_count = 0
    connections = 0
    exceptions = []
    start = time.time()

    while time.time() - start < duration_s:
        try:
            max_msgs_this_conn = 1 if connection_type == "reconnect" else random.randint(*reconnect_range)
            msgs_in_conn = 0

            if active_proto == "mqtt" and mqtt is not None:
                if hasattr(mqtt, "CallbackAPIVersion"):
                    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"{device_id}-{connections}")
                else:
                    client = mqtt.Client(client_id=f"{device_id}-{connections}")
                client.tls_set_context(ctx)
                client.tls_insecure_set(True)
                client.connect(server_ip, server_port, keepalive=60)
                client.loop_start()
                connections += 1

                try:
                    while time.time() - start < duration_s and msgs_in_conn < max_msgs_this_conn:
                        size = random.randint(*profile["payload_size"])
                        payload = _make_payload(device_id, profile_name, msg_count, size)
                        topic = f"iot/{profile_name}/{device_id}"
                        info = client.publish(topic, payload, qos=1)
                        info.wait_for_publish(timeout=5.0)
                        msg_count += 1
                        msgs_in_conn += 1

                        wait = max(0.02, random.gauss(interval_mean, interval_std))
                        logger.info(
                            f"[{device_id:<12} | MQTT-TLS] Telemetry #{msg_count:03d} ({len(payload)}B) -> next in ~{wait:.2f}s"
                        )
                        if time.time() - start < duration_s:
                            time.sleep(wait)
                finally:
                    client.loop_stop()
                    client.disconnect()

            elif active_proto == "https":
                raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw.settimeout(10)
                tls = ctx.wrap_socket(raw, server_hostname=server_ip)
                tls.connect((server_ip, server_port))
                connections += 1

                try:
                    while time.time() - start < duration_s and msgs_in_conn < max_msgs_this_conn:
                        size = random.randint(*profile["payload_size"])
                        body = _make_payload(device_id, profile_name, msg_count, size)
                        conn_hdr = "close" if (connection_type == "reconnect" or msgs_in_conn + 1 >= max_msgs_this_conn) else "keep-alive"
                        req = (
                            f"POST /upload?device={device_id}&seq={msg_count} HTTP/1.1\r\n"
                            f"Host: {server_ip}:{server_port}\r\n"
                            f"User-Agent: IoT-Camera/{device_id}\r\n"
                            f"Content-Type: application/octet-stream\r\n"
                            f"Content-Length: {len(body)}\r\n"
                            f"Connection: {conn_hdr}\r\n\r\n"
                        ).encode("ascii") + body
                        tls.sendall(req)
                        # Read HTTP response header
                        _ = tls.recv(4096)
                        msg_count += 1
                        msgs_in_conn += 1

                        wait = max(0.02, random.gauss(interval_mean, interval_std))
                        logger.info(
                            f"[{device_id:<12} | HTTPS-POST] Frame #{msg_count:03d} ({len(body)}B) -> next in ~{wait:.2f}s"
                        )
                        if time.time() - start < duration_s:
                            time.sleep(wait)
                finally:
                    try:
                        tls.close()
                    except Exception:
                        pass

            else:
                # Legacy raw-TLS echo mode (--legacy-echo)
                raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw.settimeout(10)
                tls = ctx.wrap_socket(raw, server_hostname=server_ip)
                tls.connect((server_ip, server_port))
                connections += 1

                try:
                    while time.time() - start < duration_s and msgs_in_conn < max_msgs_this_conn:
                        sz_range = profile.get("legacy_payload_size", profile["payload_size"])
                        size = random.randint(*sz_range)
                        payload = _make_payload(device_id, profile_name, msg_count, size)
                        tls.sendall(payload)
                        msg_count += 1
                        msgs_in_conn += 1

                        wait = max(0.02, random.gauss(interval_mean, interval_std))
                        logger.info(
                            f"[{device_id:<12} | {profile_name:<18}] Telemetry #{msg_count:03d} ({len(payload):4d}B) "
                            f"[conn #{connections}: msg {msgs_in_conn}/{max_msgs_this_conn}] -> next in ~{wait:.2f}s"
                        )

                        if random.random() < profile.get("burst_probability", 0.0):
                            burst_cnt = random.randint(*profile.get("burst_count", (1, 3)))
                            for _ in range(burst_cnt):
                                b_size = random.randint(*sz_range)
                                burst = bytes(random.getrandbits(8) for _ in range(b_size))
                                tls.sendall(burst)
                                time.sleep(random.uniform(0.005, 0.05) * time_scale)

                        if time.time() - start < duration_s:
                            time.sleep(wait)
                finally:
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
        result_holder["protocol"] = active_proto


def generate_benign_traffic(
    server_ip="10.0.2.10",
    server_port=8883,
    https_port=443,
    duration_s=3600.0,
    devices=None,
    time_scale=1.0,
    legacy_echo=False,
):
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

        port = https_port if (profile_name == "smart_camera" and not legacy_echo) else server_port
        t = threading.Thread(
            target=run_iot_device,
            args=(device_id, profile_name, server_ip, port),
            kwargs={
                "duration_s": duration_s,
                "connection_type": conn_type,
                "time_scale": time_scale,
                "legacy_echo": legacy_echo,
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
    parser = argparse.ArgumentParser(description="Benign IoT traffic generator (MQTT-TLS & HTTPS)")
    parser.add_argument("--device-id", help="Single device ID to run")
    parser.add_argument("--profile", help="Profile name (for single device mode)")
    parser.add_argument("--connection", choices=["persistent", "reconnect"], default="persistent")
    parser.add_argument("--device-from-config", help="Load device ID profile & connection from devices.yaml")
    parser.add_argument("--server", default="10.0.2.10", help="Server IP")
    parser.add_argument("--port", type=int, default=None, help="Override server port (default: 8883 MQTT, 443 HTTPS)")
    parser.add_argument("--https-port", type=int, default=443, help="HTTPS port for camera uploads")
    parser.add_argument("--duration", type=float, default=3600.0, help="Duration in seconds")
    parser.add_argument("--time-scale", type=float, default=1.0)
    parser.add_argument("--legacy-echo", action="store_true", help="Use legacy raw-TLS echo mode instead of MQTT/HTTPS")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("legacy_duration", nargs="?", type=float, default=None)
    args = parser.parse_args()

    duration = args.legacy_duration if args.legacy_duration else args.duration

    if args.device_from_config:
        cfg = get_device_config(args.device_from_config)
        if not cfg:
            logger.error(f"Device '{args.device_from_config}' not found in configs/devices.yaml")
            exit(1)
        prof = cfg["profile"]
        default_port = args.https_port if (prof == "smart_camera" and not args.legacy_echo) else 8883
        run_iot_device(
            device_id=cfg["device_id"],
            profile_name=prof,
            server_ip=args.server,
            server_port=args.port or default_port,
            duration_s=duration,
            connection_type=cfg.get("connection", "persistent"),
            time_scale=args.time_scale,
            legacy_echo=args.legacy_echo,
        )
    elif args.device_id and args.profile:
        default_port = args.https_port if (args.profile == "smart_camera" and not args.legacy_echo) else 8883
        run_iot_device(
            device_id=args.device_id,
            profile_name=args.profile,
            server_ip=args.server,
            server_port=args.port or default_port,
            duration_s=duration,
            connection_type=args.connection,
            time_scale=args.time_scale,
            legacy_echo=args.legacy_echo,
        )
    else:
        generate_benign_traffic(
            server_ip=args.server,
            server_port=args.port or 8883,
            https_port=args.https_port,
            duration_s=duration,
            time_scale=args.time_scale,
            legacy_echo=args.legacy_echo,
        )
