#!/usr/bin/env python3
"""تست بار سوزان — اندازه‌گیری RPS، latency، error rate"""
import os, time, subprocess, sys, statistics
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = "http://127.0.0.1:8000"
os.environ["SOOZAN_DEV_MODE"] = "1"

def start_server():
    proc = subprocess.Popen(["bash", "run.sh"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env={**os.environ, "SOOZAN_DEV_MODE": "1"})
    for _ in range(30):
        try:
            if requests.get(f"{BASE}/health", timeout=2).status_code == 200:
                return proc
        except Exception:
            pass
        time.sleep(1)
    proc.terminate()
    raise SystemExit("❌ سرور آماده نشد")

def do_get(url):
    t0 = time.time()
    try:
        r = requests.get(url, timeout=10)
        return r.status_code, time.time() - t0
    except Exception as e:
        return -1, time.time() - t0

def load_test(name, url, requests_count, workers):
    print(f"\n━━ {name} ━━")
    print(f"   {requests_count} درخواست با {workers} worker موازی")
    
    statuses, latencies = [], []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(do_get, url) for _ in range(requests_count)]
        for f in as_completed(futures):
            code, lat = f.result()
            statuses.append(code)
            latencies.append(lat)
    total = time.time() - t0
    
    ok = statuses.count(200)
    fail = len(statuses) - ok
    rps = len(statuses) / total
    p50 = statistics.median(latencies) * 1000
    p95 = statistics.quantiles(latencies, n=20)[18] * 1000  # p95
    p99 = statistics.quantiles(latencies, n=100)[98] * 1000  # p99
    
    print(f"   ✅ {ok}/{len(statuses)} موفق · {rps:.1f} req/s")
    print(f"   ⏱  p50={p50:.0f}ms · p95={p95:.0f}ms · p99={p99:.0f}ms")
    if fail:
        print(f"   ❌ {fail} خطا")
    
    return ok, fail, rps, p50, p95, p99

def main():
    print("=" * 60)
    print("⚡ تست بار سوزان")
    print("=" * 60)
    
    proc = start_server()
    print("✅ سرور آماده")
    
    try:
        results = {}
        results["/health (سبک)"] = load_test(
            "GET /health (سبک)", f"{BASE}/health", 200, 20)
        results["/login (متوسط)"] = load_test(
            "GET /login (متوسط)", f"{BASE}/login", 100, 15)
        results["/status (متوسط)"] = load_test(
            "GET /status (متوسط)", f"{BASE}/status", 100, 15)
        results["/privacy (سنگین)"] = load_test(
            "GET /privacy (سنگین)", f"{BASE}/privacy", 80, 15)
    finally:
        proc.terminate()
        proc.wait()
        print("\n🧹 سرور بسته شد")
    
    print("\n" + "=" * 60)
    print("📊 خلاصه")
    print("=" * 60)
    total_rps = 0
    for name, (ok, fail, rps, p50, p95, p99) in results.items():
        total_rps += rps
        status = "✅" if fail == 0 else "⚠️"
        print(f"{status} {name}: {ok}/{ok+fail} · {rps:.0f}rps · p95={p95:.0f}ms")
    
    print(f"\n📈 مجموع ظرفیت اندازه‌گیری‌شده: ~{total_rps:.0f} req/s")
    
    # قضاوت
    health_rps = results["/health (سبک)"][2]
    if health_rps >= 50:
        print("🏆 ظرفیت برای Termux/تست کافی است")
    else:
        print(f"⚠️  ظرفیت کم ({health_rps:.0f}rps) — در production باید بهینه شود")

if __name__ == "__main__":
    main()
