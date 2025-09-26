#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
<<<<<<< HEAD
wifi_scanner.py

Пассивный сканер Wi-Fi (monitor mode) с:
 - Автопереводом интерфейса в monitor и возвратом в managed (по умолчанию)
 - Channel hopping по ВСЕМ каналам (2.4 + 5 ГГц; DFS опционально)
 - Таблицей AP: SSID / BSSID / Channel / Signal(dBm) / Seen clients
 - Точным "фокус-сканированием" выбранной сети: фиксируемся на её канале
   и собираем клиентов через association/reassoc/data/QoS эвристику
 - Опциональной записью PCAP

Запуск (пример):
  sudo python3 wifi_scanner.py -i wlan0 -t 20 --band all --include-dfs --hop-interval 0.35 --pcap survey.pcap

После списка сетей выберите индекс — скрипт сам переключится на канал AP и
сделает углублённый захват (по умолчанию 30 секунд), чтобы точнее собрать клиентов.

Требования:
  sudo apt install -y iw
  sudo pip3 install scapy prettytable
"""

import argparse
import subprocess
import sys
import time
import threading
from collections import defaultdict
from typing import List, Tuple, Dict, Set, Optional

from prettytable import PrettyTable
from scapy.all import (
    sniff, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt, RadioTap,
    PcapWriter, conf
)

# --------------------------- Shell helpers ---------------------------

def run(cmd: List[str]) -> Tuple[int, str]:
=======
wifi_scanner.py — пассивный сканер Wi-Fi с логированием в папку log/<timestamp>

Выходы по умолчанию сохраняются в папку:
  log/YYYY-MM-DD_HH-MM-SS/

Содержит:
 - автоматический monitor/managed
 - channel hopping (2.4/5GHz, DFS опц.)
 - таблица AP (SSID/BSSID/Channel/Band/Signal/Seen clients)
 - фокус-скан выбранной сети или всех BSSID одного SSID
 - запись PCAP survey и focus
 - сохранение APS и clients в CSV/JSON внутри папки логов
 - загрузка manuf (wireshark) и lookup vendor
"""
from __future__ import annotations
import argparse, subprocess, sys, time, threading, os, json, csv
from collections import defaultdict
from typing import List, Tuple, Dict, Set, Optional
from datetime import datetime

from prettytable import PrettyTable
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt, RadioTap, PcapWriter, conf

# Try import EAPOL for deeper heuristics
try:
    from scapy.layers.dot1x import EAPOL
    HAS_EAPOL = True
except Exception:
    HAS_EAPOL = False

# ----- constants / channel plans -----
CHANNELS_24 = list(range(1, 14))
CHANNELS_5_NODFS = [36, 40, 44, 48, 149, 153, 157, 161, 165]
CHANNELS_5_DFS = [52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140]
WS_AUTOMATED_MANUF = "https://www.wireshark.org/download/automated/data/manuf"
GITLAB_MANUF = "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf"

# ----- helper shell utils -----
def run(cmd: List[str]):
>>>>>>> 3460dfb (Update and Add .gitignore (ignore log folder and pcap files))
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return 0, out
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output

<<<<<<< HEAD
def iface_set_monitor(iface: str) -> bool:
    rc, out = run(["ip", "link", "set", iface, "down"])
    if rc != 0:
        print(f"[!] ip link down {iface}: {out.strip()}", file=sys.stderr); return False
    rc, out = run(["iw", "dev", iface, "set", "type", "monitor"])
=======
def iface_set_monitor(iface: str, flags: Optional[str] = None) -> bool:
    rc, out = run(["ip", "link", "set", iface, "down"])
    if rc != 0:
        print(f"[!] ip link down {iface}: {out.strip()}", file=sys.stderr); return False
    if flags:
        cmd = ["iw", "dev", iface, "set", "monitor"] + flags.split()
    else:
        cmd = ["iw", "dev", iface, "set", "type", "monitor"]
    rc, out = run(cmd)
>>>>>>> 3460dfb (Update and Add .gitignore (ignore log folder and pcap files))
    if rc != 0:
        print(f"[!] iw set monitor: {out.strip()}", file=sys.stderr); return False
    rc, out = run(["ip", "link", "set", iface, "up"])
    if rc != 0:
        print(f"[!] ip link up {iface}: {out.strip()}", file=sys.stderr); return False
    return True

def iface_set_managed(iface: str) -> bool:
    rc, out = run(["ip", "link", "set", iface, "down"])
    if rc != 0:
        print(f"[!] ip link down {iface}: {out.strip()}", file=sys.stderr); return False
    rc, out = run(["iw", "dev", iface, "set", "type", "managed"])
    if rc != 0:
        print(f"[!] iw set managed: {out.strip()}", file=sys.stderr); return False
    rc, out = run(["ip", "link", "set", iface, "up"])
    if rc != 0:
        print(f"[!] ip link up {iface}: {out.strip()}", file=sys.stderr); return False
    return True

def set_channel(iface: str, ch: int) -> None:
    run(["iw", "dev", iface, "set", "channel", str(ch)])

<<<<<<< HEAD
# --------------------------- Channel plans ---------------------------

# Полный 2.4 ГГц (регион JP: до 13)
CHANNELS_24 = list(range(1, 14))  # 1..13

# 5 ГГц без DFS (наиболее «тихие» для большинства карт)
CHANNELS_5_NODFS = [36, 40, 44, 48, 149, 153, 157, 161, 165]

# 5 ГГц с DFS (зависит от регдомена и карты)
CHANNELS_5_DFS = [52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
                  132, 136, 140]

def build_channel_list(band: str, include_dfs: bool) -> List[int]:
    if band == "24":
        return CHANNELS_24
    if band == "5":
        return (CHANNELS_5_NODFS + (CHANNELS_5_DFS if include_dfs else []))
    if band == "all":
        return CHANNELS_24 + CHANNELS_5_NODFS + (CHANNELS_5_DFS if include_dfs else [])
    # fallback
    return CHANNELS_24

def parse_custom_channels(arg: str) -> List[int]:
    chans = []
    for p in arg.split(","):
        p = p.strip()
        if not p: continue
        try:
            chans.append(int(p))
        except ValueError:
            pass
    return chans

# --------------------------- 802.11 helpers ---------------------------

def get_ssid(pkt) -> Optional[str]:
    if not pkt.haslayer(Dot11Elt):
        return None
=======
# ----- channels / band utils -----
def build_channel_list(band: str, include_dfs: bool) -> List[int]:
    if band == "24": return CHANNELS_24
    if band == "5": return CHANNELS_5_NODFS + (CHANNELS_5_DFS if include_dfs else [])
    if band == "all": return CHANNELS_24 + CHANNELS_5_NODFS + (CHANNELS_5_DFS if include_dfs else [])
    return CHANNELS_24

def parse_custom_channels(arg: str) -> List[int]:
    out = []
    for p in arg.split(","):
        p = p.strip()
        if not p: continue
        try: out.append(int(p))
        except Exception: pass
    return out

def band_from_channel(ch: Optional[int]) -> str:
    if ch is None: return "?"
    try: ch = int(ch)
    except Exception: return "?"
    if 1 <= ch <= 14: return "2.4G"
    if ch >= 36: return "5G"
    return "?"

# ----- 802.11 helpers -----
def get_ssid(pkt) -> Optional[str]:
    if not pkt.haslayer(Dot11Elt): return None
>>>>>>> 3460dfb (Update and Add .gitignore (ignore log folder and pcap files))
    el = pkt.getlayer(Dot11Elt)
    while el:
        if getattr(el, "ID", None) == 0:
            try:
                s = el.info.decode(errors="ignore")
                return s if s != "" else "<hidden>"
            except Exception:
                return "<hidden>"
        el = el.payload.getlayer(Dot11Elt)
    return None

def get_signal_dbm(pkt) -> Optional[int]:
    try:
        if pkt.haslayer(RadioTap) and hasattr(pkt, "dBm_AntSignal"):
            return int(pkt.dBm_AntSignal)
        rt = pkt.getlayer(RadioTap)
        if rt and hasattr(rt, "dBm_AntSignal"):
            return int(rt.dBm_AntSignal)
    except Exception:
        pass
    return None

def get_channel_from_ie(pkt) -> Optional[int]:
<<<<<<< HEAD
    """
    Извлекаем «primary channel» из IE:
     - DS Parameter Set (ID=3) -> 2.4 ГГц канал
     - HT Operation (ID=61) -> info[0] = primary channel
     - VHT Operation (ID=192) -> если есть, но primary часто в HT; используем HT если доступен
    """
    ds_ch = None
    ht_primary = None
    vht_primary = None

    if not pkt.haslayer(Dot11Elt):
        return None

=======
    ds_ch = None; ht_primary = None
    if not pkt.haslayer(Dot11Elt): return None
>>>>>>> 3460dfb (Update and Add .gitignore (ignore log folder and pcap files))
    el = pkt.getlayer(Dot11Elt)
    while el:
        elid = getattr(el, "ID", None)
        raw = bytes(el.info) if hasattr(el, "info") else b""
<<<<<<< HEAD
        if elid == 3 and len(raw) >= 1:
            ds_ch = raw[0]
        elif elid == 61 and len(raw) >= 1:
            ht_primary = raw[0]  # HT Operation: 1-й байт — primary channel
        elif elid == 192 and len(raw) >= 1:
            # VHT Op не несёт «primary» напрямую; оставляем как резерв
            vht_primary = None
        el = el.payload.getlayer(Dot11Elt)

    # приоритет: HT primary > DS > VHT (если бы вычисляли)
    if ht_primary and ht_primary > 0:
        return int(ht_primary)
    if ds_ch and ds_ch > 0:
        return int(ds_ch)
    return None

# --------------------------- Channel hopper ---------------------------

class ChannelHopper(threading.Thread):
    def __init__(self, iface: str, channels: List[int], interval: float, stop_evt: threading.Event):
        super().__init__(daemon=True)
        self.iface = iface
        self.channels = channels[:] if channels else [1]
        self.interval = max(0.1, interval)
        self.stop_evt = stop_evt
        self.current_channel = None

    def run(self):
        i = 0
        while not self.stop_evt.is_set():
            ch = self.channels[i % len(self.channels)]
            self.current_channel = ch
            set_channel(self.iface, ch)
            time.sleep(self.interval)
            i += 1

# --------------------------- Passive survey ---------------------------

def passive_survey(
    iface: str,
    duration: int,
    channels: List[int],
    hop_interval: float,
    pcap_path: Optional[str] = None
):
    """
    Общий обзор эфира с channel hopping:
     - собираем AP: SSID/BSSID/Channel/макс.Signal
     - собираем «наблюдаемых» клиентов per AP и unassociated (probe)
    """
    aps: Dict[str, Dict[str, Optional[int]]] = {}    # bssid -> {ssid, signal, channel}
    clients_by_ap: Dict[str, Set[str]] = defaultdict(set)
    unassoc_clients: Set[str] = set()

    stop_evt = threading.Event()
    hopper = ChannelHopper(iface, channels, hop_interval, stop_evt)
    hopper.start()

    pcap_writer = None
    if pcap_path:
        try:
            pcap_writer = PcapWriter(pcap_path, append=False, sync=True)
            print(f"[i] Запись PCAP: {pcap_path}")
        except Exception as e:
            print(f"[!] Не удалось открыть PCAP: {e}", file=sys.stderr)

    def handler(pkt):
        if pcap_writer:
            try: pcap_writer.write(pkt)
            except Exception: pass

        if not pkt.haslayer(Dot11):
            return
        dot = pkt.getlayer(Dot11)

        # AP обнаружение
        if pkt.haslayer(Dot11Beacon) or (dot.type == 0 and dot.subtype == 5):  # ProbeResp
=======
        if elid == 3 and len(raw) >= 1: ds_ch = raw[0]
        elif elid == 61 and len(raw) >= 1: ht_primary = raw[0]
        el = el.payload.getlayer(Dot11Elt)
    if ht_primary and ht_primary > 0: return int(ht_primary)
    if ds_ch and ds_ch > 0: return int(ds_ch)
    return None

# ----- mac/vendor utils -----
def _mac_first_octet(mac: str) -> Optional[int]:
    try: return int(mac.split(":")[0], 16)
    except Exception: return None

def is_broadcast(mac: str) -> bool:
    return mac.lower() == "ff:ff:ff:ff:ff:ff"

def is_multicast(mac: str) -> bool:
    o = _mac_first_octet(mac.lower())
    return o is not None and (o & 0x01) == 1

def is_group_or_bc(mac: Optional[str]) -> bool:
    if not mac: return False
    mac = mac.lower()
    return is_broadcast(mac) or is_multicast(mac) or mac.startswith("01:00:5e:") or mac.startswith("33:33:")

def is_unicast_client_mac(mac: Optional[str]) -> bool:
    if not mac: return False
    mac = mac.lower()
    if is_group_or_bc(mac): return False
    return True

def _download_url(url: str, path: str, timeout: int = 15) -> bool:
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "wifi-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        if not data or data.startswith(b"404") or len(data) < 100:
            raise RuntimeError(f"unexpected content (size={len(data)})")
        with open(path, "wb") as f: f.write(data)
        return True
    except Exception as e:
        print(f"[!] Не удалось скачать {url}: {e}")
        return False

def download_manuf(path: str, url: Optional[str] = None) -> bool:
    url = url or WS_AUTOMATED_MANUF
    print(f"[i] Скачиваю manuf: {url}")
    if _download_url(url, path):
        print(f"[+] Загрузил manuf в: {path}"); return True
    print("[i] Пытаюсь зеркало GitLab...")
    if _download_url(GITLAB_MANUF, path):
        print(f"[+] Загрузил manuf (GitLab) в: {path}"); return True
    print("[!] Не удалось получить manuf ни с основного URL, ни с зеркала.")
    return False

def load_manuf_map(manuf_path: str) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    if not manuf_path or not os.path.exists(manuf_path): return mapping
    with open(manuf_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"): continue
            parts = line.split()
            if len(parts) < 2: continue
            oui = parts[0].split("/")[0].lower()
            if len(oui) == 6 and all(c in "0123456789abcdef" for c in oui):
                oui = ":".join([oui[i:i+2] for i in range(0,6,2)])
            vendor = " ".join(parts[1:])
            # dedupe repeated words like "Espressif Espressif Inc."
            words, dedup = vendor.split(), []
            for w in words:
                if not dedup or dedup[-1].lower() != w.lower():
                    dedup.append(w)
            mapping[oui] = " ".join(dedup)
    return mapping

def vendor_from_mac(mac: str, manuf_map: Dict[str, str]) -> str:
    if not mac: return "-"
    mac = mac.lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) < 3: return "-"
    oui = ":".join(parts[:3])
    return manuf_map.get(oui, "-")

# ----- pcap writer helper -----
try:
    from scapy.arch.libpcap import DLT_IEEE802_11_RADIO
except Exception:
    DLT_IEEE802_11_RADIO = 127

def make_pcap_writer(path: Optional[str], append=False):
    if not path: return None
    try:
        return PcapWriter(path, append=append, sync=True, linktype=DLT_IEEE802_11_RADIO)
    except Exception as e:
        print(f"[!] Не удалось открыть PCAP {path}: {e}", file=sys.stderr)
        return None

def maybe_write(writer, pkt):
    if writer and pkt.haslayer(RadioTap) and pkt.haslayer(Dot11):
        try: writer.write(pkt)
        except Exception: pass

# ----- channel hopper -----
class ChannelHopper(threading.Thread):
    def __init__(self, iface: str, channels: List[int], interval: float, stop_evt: threading.Event):
        super().__init__(daemon=True)
        self.iface, self.channels, self.interval, self.stop_evt = iface, channels[:] or [1], max(0.1, interval), stop_evt
    def run(self):
        i = 0
        while not self.stop_evt.is_set():
            set_channel(self.iface, self.channels[i % len(self.channels)])
            time.sleep(self.interval)
            i += 1

# ----- passive survey -----
def passive_survey(iface: str, duration: int, channels: List[int], hop_interval: float,
                   pcap_path: Optional[str] = None, hop_mode: str = "hopper",
                   lenient_clients: bool = False):
    aps: Dict[str, Dict[str, Optional[int]]] = {}
    clients_by_ap: Dict[str, Set[str]] = defaultdict(set)
    unassoc_clients: Set[str] = set()

    pcap_writer = make_pcap_writer(pcap_path)

    def handler(pkt):
        maybe_write(pcap_writer, pkt)
        if not pkt.haslayer(Dot11): return
        dot = pkt.getlayer(Dot11)

        # AP discovery
        if pkt.haslayer(Dot11Beacon) or (dot.type == 0 and dot.subtype == 5):
>>>>>>> 3460dfb (Update and Add .gitignore (ignore log folder and pcap files))
            bssid = (pkt.addr2 or "").lower()
            if not bssid: return
            ssid = get_ssid(pkt) or "<hidden>"
            sig  = get_signal_dbm(pkt)
            ch   = get_channel_from_ie(pkt)
<<<<<<< HEAD

            entry = aps.get(bssid, {"ssid": ssid, "signal": -999, "channel": ch})
            if ssid and (not entry.get("ssid") or entry["ssid"] == "<hidden>"):
                entry["ssid"] = ssid
            if ch and not entry.get("channel"):
                entry["channel"] = ch
            if sig is not None and (entry.get("signal") is None or sig > entry.get("signal", -9999)):
                entry["signal"] = sig
            aps[bssid] = entry
            return

        # Probe Request — неассоциированные клиенты
        if dot.type == 0 and dot.subtype == 4:
            c = (pkt.addr2 or "").lower()
            if c and not c.startswith("ff:ff:ff"):
                unassoc_clients.add(c)
            return

        # Data/QoS Data — попытка связать client <-> bssid
        if dot.type == 2:
            a1 = (pkt.addr1 or "").lower()
            a2 = (pkt.addr2 or "").lower()
            a3 = (pkt.addr3 or "").lower()
            bssid = None
            client = None

            if a3 and a3 in aps:
                bssid = a3
                client = a1 if a1 != bssid else (a2 if a2 != bssid else None)
            else:
                if a2 in aps and a1:  # AP -> client
                    bssid, client = a2, a1
                elif a1 in aps and a2:  # client -> AP
                    bssid, client = a1, a2

            if bssid and client and not client.startswith("ff:ff:ff"):
                clients_by_ap[bssid].add(client)

    conf.iface = iface
    print(f"[+] Сканируем {duration}s, каналы: {channels} (интервал {hop_interval}s). Ctrl+C — прервать.")
    try:
        sniff(prn=handler, store=False, timeout=duration)
    except KeyboardInterrupt:
        print("\n[!] Прервано пользователем.")
    finally:
        stop_evt.set()
        hopper.join(timeout=1.0)
        if pcap_writer:
            try: pcap_writer.close()
            except Exception: pass

    return aps, clients_by_ap, unassoc_clients

# --------------------------- Focused capture ---------------------------

def focused_capture_on_ap(
    iface: str,
    bssid: str,
    channel: int,
    duration: int = 30,
    pcap_path: Optional[str] = None
) -> Tuple[Set[str], Set[str]]:
    """
    Прицельное прослушивание ТОЛЬКО канала AP.
    Стараемся точнее поймать клиентов данного BSSID.
    Возвращает: (clients_of_ap, unassoc_seen)
    """
    set_channel(iface, channel)
    time.sleep(0.1)

    clients: Set[str] = set()
    unassoc: Set[str]  = set()

    pcap_writer = None
    if pcap_path:
        try:
            pcap_writer = PcapWriter(pcap_path, append=False, sync=True)
            print(f"[i] Focus PCAP: {pcap_path}")
        except Exception as e:
            print(f"[!] Не удалось открыть PCAP (focus): {e}", file=sys.stderr)

    target = bssid.lower()

    def handler(pkt):
        if pcap_writer:
            try: pcap_writer.write(pkt)
            except Exception: pass

        if not pkt.haslayer(Dot11):
            return
        dot = pkt.getlayer(Dot11)

        # Сразу отфильтруем не относящиеся кадры для экономии
        a1 = (pkt.addr1 or "").lower()
        a2 = (pkt.addr2 or "").lower()
        a3 = (pkt.addr3 or "").lower()
        if target not in (a1, a2, a3):
            return

        # Association/Reassociation/Disassociation/Authentication — полезно для «молчащих» клиентов
        if dot.type == 0:
            # 0 = mgmt; subtype 0=AssocReq, 1=AssocResp, 2=ReassocReq, 3=ReassocResp,
            # 10=Disassoc, 11=Auth, 12=Deauth, 13=Action
            st = dot.subtype
            # Ассоциации обычно: client -> AP: a1=AP, a2=client, a3=AP
            if st in (0, 2, 11, 12, 13, 10):  # учитываем и auth/deauth/disassoc/action
                # клиент — тот, кто не равен BSSID
                cand = a2 if a2 != target else (a1 if a1 != target else None)
                if cand and not cand.startswith("ff:ff:ff"):
                    clients.add(cand)
            return

        # Data/QoS Data — связываем как и раньше
        if dot.type == 2:
            bssid = None
            client = None
            if a3 and a3 == target:
                bssid = a3
                client = a1 if a1 != bssid else (a2 if a2 != bssid else None)
            else:
                if a2 == target and a1:
                    bssid, client = a2, a1
                elif a1 == target and a2:
                    bssid, client = a1, a2
            if bssid == target and client and not client.startswith("ff:ff:ff"):
                clients.add(client)
            return

        # Probe Request — клиент «маячит» на этом канале, но без привязки
        if dot.type == 0 and dot.subtype == 4:
            c = (pkt.addr2 or "").lower()
            if c and not c.startswith("ff:ff:ff"):
                unassoc.add(c)
=======
            entry = aps.get(bssid, {"ssid": ssid, "signal": -999, "channel": ch})
            if ssid and (not entry.get("ssid") or entry["ssid"] == "<hidden>"): entry["ssid"] = ssid
            if ch and not entry.get("channel"): entry["channel"] = ch
            if sig is not None and (entry.get("signal") is None or sig > entry.get("signal", -9999)): entry["signal"] = sig
            aps[bssid] = entry
            return

        # ProbeReq
        if dot.type == 0 and dot.subtype == 4:
            c = (pkt.addr2 or "").lower()
            if is_unicast_client_mac(c): unassoc_clients.add(c)
            return

        # Data / QoS Data
        if dot.type == 2:
            a1, a2, a3 = (pkt.addr1 or "").lower(), (pkt.addr2 or "").lower(), (pkt.addr3 or "").lower()
            bssid = None; client = None
            if not lenient_clients:
                if a3 and a3 in aps:
                    bssid = a3; client = a1 if a1 != bssid else (a2 if a2 != bssid else None)
                else:
                    if a2 in aps and a1: bssid, client = a2, a1
                    elif a1 in aps and a2: bssid, client = a1, a2
            else:
                cand_bssids = [b for b in (a1,a2,a3) if b in aps]
                for bz in cand_bssids:
                    for cand in (a1,a2,a3):
                        if cand and cand != bz and is_unicast_client_mac(cand):
                            bssid, client = bz, cand; break
                    if bssid: break
            if bssid and is_unicast_client_mac(client):
                clients_by_ap[bssid].add(client)
            return

        # Control frames: PS-Poll/RTS/CTS/ACK/BA/BAReq
        if dot.type == 1 and dot.subtype in (8,9,10,11,12,13):
            a1, a2 = (pkt.addr1 or "").lower(), (pkt.addr2 or "").lower()
            for bz in (a1, a2):
                if bz in aps:
                    other = a2 if bz == a1 else a1
                    if is_unicast_client_mac(other):
                        clients_by_ap[bz].add(other)
            return

        # EAPOL
        if HAS_EAPOL and pkt.haslayer(EAPOL):
            a1, a2, a3 = (pkt.addr1 or "").lower(), (pkt.addr2 or "").lower(), (pkt.addr3 or "").lower()
            for bz in (a1, a2, a3):
                if bz in aps:
                    for cand in (a1, a2, a3):
                        if cand != bz and is_unicast_client_mac(cand):
                            clients_by_ap[bz].add(cand); return

    conf.iface = iface

    if hop_mode == "seq":
        per_ch = max(0.15, duration / max(1, len(channels)))
        print(f"[+] Скан (последовательно) ~{duration}s, каналы: {channels} (≈{per_ch:.2f}s/канал)")
        for ch in channels:
            set_channel(iface, ch)
            sniff(prn=handler, store=False, timeout=per_ch)
    else:
        stop_evt = threading.Event()
        hopper = ChannelHopper(iface, channels, hop_interval, stop_evt)
        print(f"[+] Сканируем {duration}s, каналы: {channels} (интервал {hop_interval}s). Ctrl+C — прервать.")
        hopper.start()
        try:
            sniff(prn=handler, store=False, timeout=duration)
        finally:
            stop_evt.set(); hopper.join(timeout=1.0)

    if pcap_writer:
        try: pcap_writer.close()
        except Exception: pass

    return aps, clients_by_ap, unassoc_clients

# ----- focused capture -----
def focused_capture_on_ap(iface: str, bssid: str, channel: int, duration: int = 30,
                          pcap_path: Optional[str] = None, lenient_clients: bool = False):
    set_channel(iface, channel); time.sleep(0.15)
    clients: Set[str] = set(); unassoc: Set[str] = set(); group_or_bc: Set[str] = set()
    target = (bssid or "").lower()
    writer = make_pcap_writer(pcap_path, append=True)

    def _w(pkt): maybe_write(writer, pkt)

    def handler(pkt):
        _w(pkt)
        if not pkt.haslayer(Dot11): return
        dot = pkt.getlayer(Dot11)

        a1,a2,a3 = (pkt.addr1 or "").lower(), (pkt.addr2 or "").lower(), (pkt.addr3 or "").lower()
        if target not in (a1,a2,a3):
            return

        for addr in (a1,a2,a3):
            if addr and is_group_or_bc(addr): group_or_bc.add(addr)

        # Mgmt
        if dot.type == 0:
            st = dot.subtype
            if st in (0,2,10,11,12,13):
                cand = a2 if a2 != target else (a1 if a1 != target else None)
                if is_unicast_client_mac(cand): clients.add(cand)
            if st == 4:
                c = (pkt.addr2 or "").lower()
                if is_unicast_client_mac(c): unassoc.add(c)
            return

        # Data/QoS
        if dot.type == 2:
            bssid_v = None; client = None
            if a3 and a3 == target:
                bssid_v = a3; client = a1 if a1 != bssid_v else (a2 if a2 != bssid_v else None)
            else:
                if a2 == target and a1: bssid_v, client = a2, a1
                elif a1 == target and a2: bssid_v, client = a1, a2
            if not client and lenient_clients:
                for cand in (a1,a2,a3):
                    if cand and cand != target and is_unicast_client_mac(cand):
                        client = cand; break
            if is_unicast_client_mac(client): clients.add(client)
            return

        # Control
        if dot.type == 1 and dot.subtype in (8,9,10,11,12,13):
            for bz, other in ((a1,a2),(a2,a1)):
                if bz == target and is_unicast_client_mac(other):
                    clients.add(other)
            return

        # EAPOL
        if HAS_EAPOL and pkt.haslayer(EAPOL):
            for cand in (a1,a2,a3):
                if cand != target and is_unicast_client_mac(cand):
                    clients.add(cand); return
>>>>>>> 3460dfb (Update and Add .gitignore (ignore log folder and pcap files))

    conf.iface = iface
    print(f"[+] Фокус-скан AP {bssid} на канале {channel} в течение {duration}s...")
    try:
        sniff(prn=handler, store=False, timeout=duration)
<<<<<<< HEAD
    except KeyboardInterrupt:
        print("\n[!] Прервано пользователем.")
    finally:
        if pcap_writer:
            try: pcap_writer.close()
            except Exception: pass

    return clients, unassoc

# --------------------------- UI ---------------------------

def print_ap_table(aps: Dict[str, Dict[str, Optional[int]]], clients_by_ap: Dict[str, Set[str]]):
    tbl = PrettyTable()
    tbl.field_names = ["#", "SSID", "BSSID", "Channel", "Signal (dBm)", "Seen clients"]
    rows = []
    for bssid, info in aps.items():
        ssid = info.get("ssid", "<hidden>")
        ch   = info.get("channel") if info.get("channel") else "?"
        sig  = info.get("signal") if info.get("signal") is not None else -999
        cnt  = len(clients_by_ap.get(bssid, set()))
        rows.append((bssid, ssid, ch, sig, cnt))
    rows.sort(key=lambda r: r[3], reverse=True)
    for i, (bssid, ssid, ch, sig, cnt) in enumerate(rows):
        tbl.add_row([i, ssid, bssid, ch, sig, cnt])
    print(tbl)
    return rows

# --------------------------- main ---------------------------

def main():
    ap = argparse.ArgumentParser(description="Passive Wi-Fi scanner with channel hopping and focused AP capture.")
    ap.add_argument("-i", "--iface", required=True, help="Wireless interface, e.g. wlan0")
    ap.add_argument("-t", "--sniff-time", type=int, default=20, help="Survey time (seconds) for channel hopping")
    ap.add_argument("--focus-time", type=int, default=30, help="Focused capture time on selected AP (seconds)")
    ap.add_argument("--band", choices=["24", "5", "all", "custom"], default="all", help="Bands to survey")
    ap.add_argument("--include-dfs", action="store_true", help="Include DFS channels for 5 GHz/all")
    ap.add_argument("--channels", help="Custom channels, e.g. '1,6,11,36,40' (requires --band custom)")
    ap.add_argument("--hop-interval", type=float, default=0.35, help="Hop dwell time per channel (>=0.1s)")
    ap.add_argument("--pcap", dest="pcap_path", help="Write survey PCAP")
    ap.add_argument("--focus-pcap", dest="focus_pcap_path", help="Write focused AP PCAP")
    ap.add_argument("--no-auto-monitor", action="store_true", help="Assume iface already in monitor")
    ap.add_argument("--keep-monitor", action="store_true", help="Keep monitor mode on exit")
    args = ap.parse_args()

    # Список каналов
=======
    finally:
        if writer:
            try: writer.close()
            except Exception: pass

    return clients, unassoc, group_or_bc

# ----- utils: save outputs to log dir -----
def make_log_dir(base="log"):
    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    d = os.path.join(base, now)
    os.makedirs(d, exist_ok=True)
    return d

def save_aps_csv_json(aps: Dict[str, Dict[str, Optional[int]]], clients_by_ap: Dict[str, Set[str]], out_dir: str):
    csv_path = os.path.join(out_dir, "aps.csv")
    json_path = os.path.join(out_dir, "aps.json")
    # CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["BSSID","SSID","Channel","Band","Signal(dBm)","SeenClients"])
        for bssid, info in aps.items():
            ssid = info.get("ssid","<hidden>")
            ch = info.get("channel") or "?"
            band = band_from_channel(ch if ch!="?" else None)
            sig = info.get("signal") if info.get("signal") is not None else ""
            cnt = len(clients_by_ap.get(bssid, set()))
            w.writerow([bssid, ssid, ch, band, sig, cnt])
    # JSON
    data = []
    for bssid, info in aps.items():
        ssid = info.get("ssid","<hidden>")
        ch = info.get("channel") or "?"
        band = band_from_channel(ch if ch!="?" else None)
        sig = info.get("signal") if info.get("signal") is not None else ""
        cnt = len(clients_by_ap.get(bssid, set()))
        data.append({"bssid": bssid, "ssid": ssid, "channel": ch, "band": band, "signal": sig, "seen_clients": cnt})
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    print(f"[+] AP-таблица сохранена в CSV: {csv_path}")
    print(f"[+] AP-таблица сохранена в JSON: {json_path}")

def save_clients_csv_json(clients: Set[str], unassoc: Set[str], groups: Set[str], manuf_map: Dict[str,str], out_dir: str):
    csv_path = os.path.join(out_dir, "clients.csv")
    json_path = os.path.join(out_dir, "clients.json")
    rows = []
    for c in sorted(clients):
        rows.append({"mac": c, "vendor": vendor_from_mac(c, manuf_map), "type": "client"})
    for u in sorted(unassoc):
        rows.append({"mac": u, "vendor": vendor_from_mac(u, manuf_map), "type": "probe"})
    for g in sorted(groups):
        typ = "broadcast" if g.lower()=="ff:ff:ff:ff:ff:ff" else ("multicast" if is_multicast(g) else "group")
        rows.append({"mac": g, "vendor": vendor_from_mac(g, manuf_map), "type": typ})
    # CSV
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["MAC","Vendor","Type"])
        for r in rows:
            w.writerow([r["mac"], r["vendor"], r["type"]])
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, ensure_ascii=False, indent=2)
    print(f"[+] Клиенты сохранены в CSV: {csv_path}")
    print(f"[+] Клиенты сохранены в JSON: {json_path}")

# ----- printing UI -----
def print_ap_table(aps: Dict[str, Dict[str, Optional[int]]], clients_by_ap: Dict[str, Set[str]]):
    tbl = PrettyTable()
    tbl.field_names = ["#", "SSID", "BSSID", "Channel", "Band", "Signal (dBm)", "Seen clients"]
    rows = []
    for bssid, info in aps.items():
        ssid = info.get("ssid", "<hidden>")
        ch   = info.get("channel")
        band = band_from_channel(ch)
        ch_out = ch if ch is not None else "?"
        sig  = info.get("signal") if info.get("signal") is not None else -999
        cnt  = len(clients_by_ap.get(bssid, set()))
        rows.append((bssid, ssid, ch_out, band, sig, cnt))
    rows.sort(key=lambda r: r[4], reverse=True)
    for i, (bssid, ssid, ch_out, band, sig, cnt) in enumerate(rows):
        tbl.add_row([i, ssid, bssid, ch_out, band, sig, cnt])
    print(tbl)
    return rows

# ----- main -----
def main():
    ap = argparse.ArgumentParser(description="Passive Wi-Fi scanner with logging")
    ap.add_argument("-i", "--iface", required=True)
    ap.add_argument("-t", "--sniff-time", type=int, default=20)
    ap.add_argument("--focus-time", type=int, default=30)
    ap.add_argument("--band", choices=["24","5","all","custom"], default="all")
    ap.add_argument("--include-dfs", action="store_true")
    ap.add_argument("--channels")
    ap.add_argument("--hop-interval", type=float, default=0.35)
    ap.add_argument("--hop-mode", choices=["hopper","seq"], default="hopper")
    ap.add_argument("--monitor-flags", default="otherbss fcsfail control")

    ap.add_argument("--pcap", dest="pcap_path")
    ap.add_argument("--focus-pcap", dest="focus_pcap_path")
    ap.add_argument("--no-auto-monitor", action="store_true")
    ap.add_argument("--keep-monitor", action="store_true")

    ap.add_argument("--download-manuf", action="store_true")
    ap.add_argument("--manuf-url")
    ap.add_argument("--oui-manuf")

    ap.add_argument("--lenient-clients", action="store_true")
    ap.add_argument("--focus-ssid-all", action="store_true")

    args = ap.parse_args()

    # create log dir
    log_dir = make_log_dir("log")
    print(f"[i] Выходные файлы текущего запуска будут сохранены в: {log_dir}")

    # if user provided pcap paths, place them inside log dir by basename
    if args.pcap_path:
        args.pcap_path = os.path.join(log_dir, os.path.basename(args.pcap_path))
    if args.focus_pcap_path:
        args.focus_pcap_path = os.path.join(log_dir, os.path.basename(args.focus_pcap_path))

    # manuf download & load map (saved into log dir if downloaded)
    manuf_target = args.oui_manuf or os.path.join(log_dir, "manuf")
    if args.download_manuf:
        download_manuf(manuf_target, url=args.manuf_url)
    manuf_map = {}
    if args.oui_manuf and os.path.exists(args.oui_manuf):
        manuf_map = load_manuf_map(args.oui_manuf)
    elif os.path.exists(manuf_target):
        manuf_map = load_manuf_map(manuf_target)

    # channels
>>>>>>> 3460dfb (Update and Add .gitignore (ignore log folder and pcap files))
    if args.band == "custom":
        if not args.channels:
            print("[!] --band custom требует --channels", file=sys.stderr); sys.exit(2)
        channels = parse_custom_channels(args.channels)
        if not channels:
            print("[!] Пустой список каналов.", file=sys.stderr); sys.exit(2)
    else:
        channels = build_channel_list(args.band, args.include_dfs)

    iface = args.iface
    monitor_set = False
<<<<<<< HEAD

    try:
        if not args.no_auto_monitor:
            print(f"[i] Переводим {iface} в monitor mode...")
            if iface_set_monitor(iface):
                monitor_set = True
                print(f"[+] {iface} -> monitor")
            else:
                print("[!] Не удалось автоматически включить monitor. Продолжим как есть...")

        # 1) Обзор с хоппингом
        aps, clients_by_ap, unassoc = passive_survey(
            iface=iface,
            duration=args.sniff_time,
            channels=channels,
            hop_interval=args.hop_interval,
            pcap_path=args.pcap_path
        )

        if not aps:
            print("[!] Не найдено AP. Проверьте регдомен/каналы/питание адаптера.")
            return

        rows = print_ap_table(aps, clients_by_ap)

        # 2) Выбор AP -> прицельный захват на канале AP
        sel = input("Введите # сети для точного подсчёта клиентов (Enter — выход): ").strip()
        if sel == "":
            return
=======
    try:
        if not args.no_auto_monitor:
            print(f"[i] Переводим {iface} в monitor mode...")
            if iface_set_monitor(iface, flags=args.monitor_flags):
                monitor_set = True
                print(f"[+] {iface} -> monitor ({args.monitor_flags})")
            else:
                print("[!] Не удалось автоматически включить monitor. Продолжим как есть...")

        # passive survey
        aps, clients_by_ap, unassoc = passive_survey(
            iface=iface, duration=args.sniff_time, channels=channels,
            hop_interval=args.hop_interval, pcap_path=args.pcap_path,
            hop_mode=args.hop_mode, lenient_clients=args.lenient_clients
        )

        if not aps:
            print("[!] Не найдено AP. Проверьте регдомен/каналы/питание адаптера."); return

        rows = print_ap_table(aps, clients_by_ap)

        # save aps to log
        save_aps_csv_json(aps, clients_by_ap, log_dir)

        sel = input("Введите # сети для точного подсчёта клиентов (Enter — выход): ").strip()
        if sel == "": return
>>>>>>> 3460dfb (Update and Add .gitignore (ignore log folder and pcap files))
        try:
            idx = int(sel)
            if idx < 0 or idx >= len(rows):
                print("Неправильный индекс."); return
        except ValueError:
            print("Введите число."); return

<<<<<<< HEAD
        bssid = rows[idx][0]
        ssid  = rows[idx][1]
        ch    = rows[idx][2]
        if ch == "?":
            # если канал не распознан из Beacon, попробуем разумный fallback: 1
            ch = 1
            print("[i] Канал AP не найден в IE; фиксируемся на канале 1 (можно задать вручную через --channels).")

        print(f"[i] Фокус на {ssid} ({bssid}), канал {ch}")
        clients, unassoc_focus = focused_capture_on_ap(
            iface=iface,
            bssid=bssid,
            channel=int(ch),
            duration=args.focus_time,
            pcap_path=args.focus_pcap_path
        )

        # Вывод результатов фокуса
        print(f"\nAP: {ssid} ({bssid})  channel {ch}")
        print(f"Найдено клиентов: {len(clients)}")
        if clients:
            t2 = PrettyTable()
            t2.field_names = ["#", "Client MAC"]
            for i, c in enumerate(sorted(clients)):
                t2.add_row([i, c])
            print(t2)
        else:
            print("Клиенты не обнаружены. Увеличьте --focus-time и повторите.")

        if unassoc_focus:
            print(f"\nUnassociated (probe) на этом канале: {len(unassoc_focus)}")
            t3 = PrettyTable()
            t3.field_names = ["#", "Client MAC"]
            for i, c in enumerate(sorted(unassoc_focus)):
                t3.add_row([i, c])
            print(t3)
=======
        bssid = rows[idx][0]; ssid = rows[idx][1]; ch = rows[idx][2]; band = rows[idx][3]
        if ch == "?":
            ch = 1; print("[i] Канал AP не найден в IE; фиксируемся на канале 1.")

        if args.focus_ssid_all and ssid != "<hidden>":
            siblings = []
            for (b2, s2, ch2, band2, _, _) in rows:
                if s2 == ssid:
                    siblings.append((b2, ch2 if ch2 != "?" else 1, band2))
            uniq = []
            seen = set()
            for b2, ch2, band2 in siblings:
                key = (b2, int(ch2))
                if key not in seen:
                    seen.add(key); uniq.append((b2, int(ch2), band2))
            print(f"[i] Фокус по всем BSSID SSID='{ssid}' ({len(uniq)} шт.): {[(u[0], u[1], u[2]) for u in uniq]}")
            all_clients, all_unassoc, all_groups = set(), set(), set()
            for (b2, ch2, band2) in uniq:
                print(f"[i] Фокус по {ssid} ({band2}) BSSID={b2}, канал {ch2}")
                c2, u2, g2 = focused_capture_on_ap(
                    iface=iface, bssid=b2, channel=int(ch2),
                    duration=args.focus_time, pcap_path=args.focus_pcap_path,
                    lenient_clients=args.lenient_clients
                )
                print(f"   └─ найдено клиентов: {len(c2)}  (probe: {len(u2)})")
                all_clients |= c2; all_unassoc |= u2; all_groups |= g2

            print(f"\nSSID: {ssid}")
            print(f"Скан BSSIDs: {', '.join([u[0] for u in uniq])}")
            print(f"Найдено клиентов (unicast): {len(all_clients)}   (probe замечены: {len(all_unassoc)})")
            if all_clients:
                t2 = PrettyTable(); t2.field_names = ["#", "Client MAC", "Vendor"]
                for i, c in enumerate(sorted(all_clients)):
                    t2.add_row([i, c, vendor_from_mac(c, manuf_map)])
                print(t2)
            else:
                print("Клиенты не обнаружены. Увеличьте --focus-time/раунды и перезапустите при активности клиентов.")

            if all_unassoc:
                print(f"\nUnassociated (probe) на каналах SSID: {len(all_unassoc)}")
                t3 = PrettyTable(); t3.field_names = ["#", "Client MAC", "Vendor"]
                for i, c in enumerate(sorted(all_unassoc)):
                    t3.add_row([i, c, vendor_from_mac(c, manuf_map)])
                print(t3)

            if all_groups:
                print(f"\nGroup/BC (не клиенты): {len(all_groups)}")
                tg = PrettyTable(); tg.field_names = ["#", "MAC", "Тип", "Vendor"]
                for i, g in enumerate(sorted(all_groups)):
                    typ = "broadcast" if g.lower()=="ff:ff:ff:ff:ff:ff" else ("multicast" if is_multicast(g) else "group")
                    tg.add_row([i, g, typ, vendor_from_mac(g, manuf_map)])
                print(tg)

            # save clients
            save_clients_csv_json(all_clients, all_unassoc, all_groups, manuf_map, log_dir)

        else:
            print(f"[i] Фокус на {ssid} ({bssid}), канал {ch}")
            clients, unassoc_focus, groups = focused_capture_on_ap(
                iface=iface, bssid=bssid, channel=int(ch),
                duration=args.focus_time, pcap_path=args.focus_pcap_path,
                lenient_clients=args.lenient_clients
            )

            print(f"\nAP: {ssid} ({bssid})  channel {ch}")
            print(f"Найдено клиентов: {len(clients)}")
            if clients:
                t2 = PrettyTable(); t2.field_names = ["#", "Client MAC", "Vendor"]
                for i, c in enumerate(sorted(clients)):
                    t2.add_row([i, c, vendor_from_mac(c, manuf_map)])
                print(t2)
            else:
                print("Клиенты не обнаружены.")

            if unassoc_focus:
                print(f"\nUnassociated (probe) на этом канале: {len(unassoc_focus)}")
                t3 = PrettyTable(); t3.field_names = ["#", "Client MAC", "Vendor"]
                for i, c in enumerate(sorted(unassoc_focus)):
                    t3.add_row([i, c, vendor_from_mac(c, manuf_map)])
                print(t3)

            if groups:
                print(f"\nGroup/BC (не клиенты): {len(groups)}")
                tg = PrettyTable(); tg.field_names = ["#", "MAC", "Тип", "Vendor"]
                for i, g in enumerate(sorted(groups)):
                    typ = "broadcast" if g.lower()=="ff:ff:ff:ff:ff:ff" else ("multicast" if is_multicast(g) else "group")
                    tg.add_row([i, g, typ, vendor_from_mac(g, manuf_map)])
                print(tg)

            # save clients
            save_clients_csv_json(clients, unassoc_focus, groups, manuf_map, log_dir)
>>>>>>> 3460dfb (Update and Add .gitignore (ignore log folder and pcap files))

    finally:
        if monitor_set and not args.keep_monitor:
            print("[i] Возвращаем интерфейс в managed...")
<<<<<<< HEAD
            if iface_set_managed(iface):
                print("[+] Готово (managed).")
            else:
                print("[!] Не удалось вернуть managed — сделайте вручную.")
            
=======
            if iface_set_managed(iface): print("[+] Готово (managed).")
            else: print("[!] Не удалось вернуть managed — сделайте вручную.")
>>>>>>> 3460dfb (Update and Add .gitignore (ignore log folder and pcap files))

if __name__ == "__main__":
    main()
