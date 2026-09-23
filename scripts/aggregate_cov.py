import json, collections, sys

with open(sys.argv[1]) as f:
    data = json.load(f)

files = data['data'][0]['files']
crates = collections.defaultdict(lambda: {'regions': [0,0], 'functions': [0,0], 'lines': [0,0]})

for f in files:
    path = f['filename']
    parts = path.replace('\\', '/').split('/')
    try:
        idx = parts.index('crates')
        crate = parts[idx+1]
    except ValueError:
        if 'src' in parts:
            idx = parts.index('src')
            crate = parts[idx-1] if idx > 0 else 'root'
        else:
            crate = 'root'
    s = f['summary']
    crates[crate]['regions'][0] += s['regions']['covered']
    crates[crate]['regions'][1] += s['regions']['count']
    crates[crate]['functions'][0] += s['functions']['covered']
    crates[crate]['functions'][1] += s['functions']['count']
    crates[crate]['lines'][0] += s['lines']['covered']
    crates[crate]['lines'][1] += s['lines']['count']

print(f'{"Crate":<20} {"Regions":>10} {"Functions":>10} {"Lines":>10}')
print('-'*56)
total = {'regions': [0, 0], 'functions': [0, 0], 'lines': [0, 0]}
for crate in sorted(crates.keys()):
    v = crates[crate]
    r = v['regions'][0]/v['regions'][1]*100 if v['regions'][1] else 0
    fn = v['functions'][0]/v['functions'][1]*100 if v['functions'][1] else 0
    ln = v['lines'][0]/v['lines'][1]*100 if v['lines'][1] else 0
    print(f'{crate:<20} {r:>9.2f}% {fn:>9.2f}% {ln:>9.2f}%')
    for k in total:
        total[k][0] += v[k][0]
        total[k][1] += v[k][1]

print('-'*56)
r = total['regions'][0]/total['regions'][1]*100 if total['regions'][1] else 0
fn = total['functions'][0]/total['functions'][1]*100 if total['functions'][1] else 0
ln = total['lines'][0]/total['lines'][1]*100 if total['lines'][1] else 0
print(f'{"TOTAL":<20} {r:>9.2f}% {fn:>9.2f}% {ln:>9.2f}%')
