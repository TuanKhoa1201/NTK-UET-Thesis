import glob
import yaml

specs_files = glob.glob("/home/tuankhoa/iris/output/**/specs.model.yml", recursive=True)
print(f"Total specs.model.yml: {len(specs_files)}")

all_sinks = set()
all_sources = set()

for sf in specs_files:
    try:
        with open(sf, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not data or "extensions" not in data:
                continue
            for ext in data["extensions"]:
                adds_to = ext.get("addsTo", {}).get("extensible", "")
                rows = ext.get("data", [])
                if adds_to == "sinkModel":
                    for r in rows:
                        # [package, class, bool, method, sig, ?, sink_arg, project, mode]
                        all_sinks.add((r[0], r[1], r[3], str(r[6])))
                elif adds_to == "sourceModel":
                    for r in rows:
                        all_sources.add((r[0], r[1], r[3]))
    except Exception as e:
        pass

print(f"Unique Sinks found in output specs: {len(all_sinks)}")
print(f"Unique Sources found in output specs: {len(all_sources)}")
print("Sample Sinks:")
for s in list(all_sinks)[:15]:
    print("  ", s)
print("Sample Sources:")
for s in list(all_sources)[:10]:
    print("  ", s)
