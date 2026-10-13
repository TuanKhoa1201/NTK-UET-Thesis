import pandas as pd

df = pd.read_csv('/home/tuankhoa/iris/data/fix_info_source_sink.csv')
for idx, row in df.iterrows():
    print(f"[{idx+1}] CVE: {row['cve_id']}, Class: {row['class']}, Method: {row['method']}")
    print(f"    Source CodeQL: {row['Source CodeQl  Format']}")
    print(f"    Sink CodeQL: {row['Sink CodeQl Format']}")
    if idx >= 9:
        break
