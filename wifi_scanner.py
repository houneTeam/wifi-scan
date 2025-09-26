#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
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
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        return 0, out
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output

def iface_set_monitor(iface: str) -> bool:
    rc, out = run(["ip", "link", "set", iface, "down"])
    if rc != 0:
        print(f"[!] ip link down {iface}: {out.strip()}", file=sys.stderr); return False
    rc, out = run(["iw", "dev", iface, "set", "type", "monitor"])
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

    el = pkt.getlayer(Dot11Elt)
    while el:
        elid = getattr(el, "ID", None)
        raw = bytes(el.info) if hasattr(el, "info") else b""
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
            bssid = (pkt.addr2 or "").lower()
            if not bssid: return
            ssid = get_ssid(pkt) or "<hidden>"
            sig  = get_signal_dbm(pkt)
            ch   = get_channel_from_ie(pkt)

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

    conf.iface = iface
    print(f"[+] Фокус-скан AP {bssid} на канале {channel} в течение {duration}s...")
    try:
        sniff(prn=handler, store=False, timeout=duration)
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
        try:
            idx = int(sel)
            if idx < 0 or idx >= len(rows):
                print("Неправильный индекс."); return
        except ValueError:
            print("Введите число."); return

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

    finally:
        if monitor_set and not args.keep_monitor:
            print("[i] Возвращаем интерфейс в managed...")
            if iface_set_managed(iface):
                print("[+] Готово (managed).")
            else:
                print("[!] Не удалось вернуть managed — сделайте вручную.")
            

if __name__ == "__main__":
    main()
