import csv

path = "/home/tuankhoa/iris/output/owasp_benchmark_CVE-2026-0005_1.0/owasp_benchmark_CVE-2026-0005_1.0/manual-local-production-v1/fetch_external_apis/results.csv"

apis = set()
with open(path, "r", encoding="utf-8", errors="replace") as f:
    reader = csv.DictReader(f)
    for row in reader:
        pkg = row.get("package", "")
        clazz = row.get("clazz", "")
        func = row.get("func", "")
        sig = row.get("full_signature", "")
        if pkg and clazz and func:
            apis.add((pkg, clazz, func, sig))

print(f"Total unique APIs in OWASP Benchmark external calls: {len(apis)}")
print("Sample 20 APIs:")
for a in sorted(list(apis))[:20]:
    print(" ", a)
