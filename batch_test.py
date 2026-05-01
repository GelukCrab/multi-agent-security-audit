"""批量测试sqli-labs所有关卡"""

import subprocess
import sys
import time
from datetime import datetime

BASE_URL = "http://localhost:83"
START_LEVEL = 6
END_LEVEL = 65

results = []

for level in range(START_LEVEL, END_LEVEL + 1):
    url = f"{BASE_URL}/Less-{level}/"
    print(f"\n{'='*60}")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 开始测试 Less-{level}")
    print(f"{'='*60}")

    start = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "src.main", "-t", url],
            capture_output=True, text=True, encoding="utf-8",
            timeout=600,
            cwd=r"C:\Users\27351\Desktop\multi-agent-security-audit",
        )
        elapsed = time.time() - start
        output = proc.stdout + proc.stderr

        if "发现漏洞" in output or "finding_id" in output:
            status = "PASS"
        elif "LLM调用失败" in output:
            status = "ERROR"
        else:
            status = "FAIL"

        results.append({
            "level": level,
            "status": status,
            "time": round(elapsed, 1),
        })
        print(f"[Less-{level}] {status} ({elapsed:.1f}s)")

    except subprocess.TimeoutExpired:
        results.append({"level": level, "status": "TIMEOUT", "time": 600})
        print(f"[Less-{level}] TIMEOUT")
    except Exception as e:
        results.append({"level": level, "status": "ERROR", "time": 0})
        print(f"[Less-{level}] ERROR: {e}")

print(f"\n{'='*60}")
print("测试结果汇总")
print(f"{'='*60}")
passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
errors = sum(1 for r in results if r["status"] in ("ERROR", "TIMEOUT"))
print(f"通过: {passed} | 失败: {failed} | 错误: {errors} | 总计: {len(results)}")
print()
for r in results:
    icon = "✅" if r["status"] == "PASS" else "❌" if r["status"] == "FAIL" else "⚠️"
    print(f"  {icon} Less-{r['level']:>2}: {r['status']:>7} ({r['time']}s)")
