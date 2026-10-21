import os, sys, json, ast, time
from pathlib import Path

repo_root = Path('F:/repository-compiler')

modules = {}
total_lines = 0
total_funcs = 0
total_classes = 0

for p in repo_root.rglob('*.py'):
    path_str = str(p)
    if '__pycache__' in path_str or '.rc_workspace' in path_str or 'external_component_candidates' in path_str:
        continue
    rel = str(p.relative_to(repo_root)).replace('\\', '/')
    try:
        content = p.read_text(encoding='utf-8', errors='ignore')
        lines = len(content.splitlines())
        tree = ast.parse(content)
        funcs = len([n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))])
        classes = len([n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)])
        subsystem = rel.split('/')[0] if '/' in rel else 'root'
        if subsystem not in modules:
            modules[subsystem] = {'files': 0, 'lines': 0, 'functions': 0, 'classes': 0, 'file_list': []}
        modules[subsystem]['files'] += 1
        modules[subsystem]['lines'] += lines
        modules[subsystem]['functions'] += funcs
        modules[subsystem]['classes'] += classes
        modules[subsystem]['file_list'].append(rel)
        total_lines += lines
        total_funcs += funcs
        total_classes += classes
    except Exception as e:
        pass

summary = {
    'repository': 'omnicompiler',
    'total_files': sum(m['files'] for m in modules.values()),
    'total_lines': total_lines,
    'total_functions': total_funcs,
    'total_classes': total_classes,
    'subsystems': modules,
    'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ')
}

out_path = repo_root / 'external_component_candidates' / 'evidence' / 'baseline_audit.json'
out_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')
print(f"Audited {summary['total_files']} files, {total_lines} lines across {len(modules)} subsystems.")
for s, data in sorted(modules.items()):
    print(f"  {s:15s}: {data['files']:2d} files, {data['lines']:5d} lines, {data['classes']:3d} classes, {data['functions']:3d} funcs")
