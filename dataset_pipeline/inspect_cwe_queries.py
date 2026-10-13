import sys
sys.path.append("/home/tuankhoa/iris")
from src.queries import QUERIES

cwe_queries = [k for k in QUERIES.keys() if k.startswith("cwe-") and "wLLM" in k]
print(f"Supported CWE queries with LLM: {cwe_queries}")

for qk in cwe_queries:
    q = QUERIES[qk]
    prompts = q.get("prompts", {})
    cwe_id = prompts.get("cwe_id", "")
    desc = prompts.get("desc", "")
    examples = prompts.get("examples", [])
    print(f"\n--- {qk} ({cwe_id}): {desc} ---")
    print(f"Example count: {len(examples)}")
    types = [e.get("type") for e in examples]
    print(f"Example types: {set(types)} -> {types}")
