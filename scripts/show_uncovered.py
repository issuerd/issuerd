import re, glob, os

def show_uncovered(html_path):
    html = open(html_path, 'r', encoding='utf-8').read()
    rows = re.findall(r'<tr>(.*?)</tr>', html, re.DOTALL)
    uncovered = []
    for row in rows:
        m = re.search(r"<a name='L(\d+)'", row)
        if not m:
            continue
        line_no = int(m.group(1))
        if 'uncovered-line' in row:
            code_m = re.search(r"<td class='code'><pre>(.*?)</pre></td>", row)
            code = code_m.group(1) if code_m else ""
            code = code.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')
            uncovered.append((line_no, code))
    return uncovered

base = 'target/llvm-cov/html/coverage/dev/issuerd/crates/issuerd-server/src'
for html in sorted(glob.glob(base + '/**/*.rs.html', recursive=True)):
    rel = os.path.relpath(html, base)
    src_file = rel.replace('.html', '')
    lines = show_uncovered(html)
    if not lines:
        continue
    print(f"\n=== {src_file} ({len(lines)} uncovered lines) ===")
    for lineno, code in lines:
        print(f"  {lineno:4d}: {code}")
