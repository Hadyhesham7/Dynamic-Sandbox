import json

# Try api_raw_report.json first
r = json.load(open('server_report/api_raw_report.json'))
if 'behavior' in r:
    calls = r['behavior']['processes'][0]['calls']
else:
    calls = r  # might be a list

print(f"Total calls: {len(calls)}")

# Find self-test entries
selftest = [c for c in calls if '__selftest' in c.get('api', '')]
print(f"\n=== SELF-TEST ENTRIES: {len(selftest)} ===")
for s in selftest:
    print(json.dumps(s, indent=2))

# Find CreateFileW/VirtualAlloc from the test
cfw = [c for c in calls if c.get('api') == 'CreateFileW']
va = [c for c in calls if c.get('api') == 'VirtualAlloc']
conn = [c for c in calls if c.get('api') == 'connect']
sock = [c for c in calls if c.get('api') == 'socket']
print(f"\nCreateFileW: {len(cfw)}")
print(f"VirtualAlloc: {len(va)}")
print(f"connect: {len(conn)}")
print(f"socket: {len(sock)}")

# Show first few CreateFileW if any
for c in cfw[:3]:
    print(f"  t={c.get('time',0):.3f} {json.dumps(c.get('args', c.get('arguments',{})))[:150]}")

# Categories
cats = {}
apis = {}
for c in calls:
    cat = c.get('cat', c.get('category', '?'))
    api = c.get('api', '?')
    cats[cat] = cats.get(cat, 0) + 1
    apis[api] = apis.get(api, 0) + 1
print(f"\nCategories: {cats}")
print(f"\nAll APIs: {json.dumps(apis, indent=2)}")
