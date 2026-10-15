#!/usr/bin/env python3
"""
traffic/benign_iot_generator.py — benign IoT telemetry over TLS.
Usage: sudo ip netns exec iot1 python3 traffic/benign_iot_generator.py [seconds]
"""
import ssl
import socket
import time
import random
import json
import threading
import logging

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


def run_iot_device(device_id, profile_name, server_ip, server_port=8883, duration_s=3600.0):
    profile = PROFILES[profile_name]
    interval_mean, interval_std = profile["interval_s"]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    msg_count = 0
    start = time.time()
    while time.time() - start < duration_s:
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(10)
            tls = ctx.wrap_socket(raw, server_hostname=server_ip)
            tls.connect((server_ip, server_port))
            logger.info(f"[{device_id}] connected")

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

                if random.random() < profile["burst_probability"]:
                    for _ in range(random.randint(*profile["burst_count"])):
                        burst = bytes(random.getrandbits(8)
                                      for _ in range(random.randint(*profile["payload_size"])))
                        tls.sendall(burst)
                        time.sleep(random.uniform(0.01, 0.1))

                wait = max(0.1, random.gauss(interval_mean, interval_std))
                time.sleep(wait)
            tls.close()
        except Exception as e:
            logger.warning(f"[{device_id}] connection error: {e}")
            time.sleep(5)
    logger.info(f"[{device_id}] done, sent {msg_count} messages")


def generate_benign_traffic(server_ip="10.0.2.10", server_port=8883, duration_s=3600.0):
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
    for device_id, profile_name in devices:
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
    import sys
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 3600.0
    generate_benign_traffic(duration_s=duration)
