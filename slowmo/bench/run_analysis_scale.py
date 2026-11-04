#!/usr/bin/env python3
"""Reproducible scale/cold-cache/warm-cache/cancellation matrix.

A supplied real trace is hard-linked into a private directory: its original
index and pass cache are never removed. Synthetic data are labelled as such.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile
import time

p = argparse.ArgumentParser()
p.add_argument('--binary', type=Path, default=Path('slowmo/build-no-triton/bench_analysis_scale'))
p.add_argument('--scales', default='100000,1000000,10000000')
p.add_argument('--formats', default='v4,v5,block')
p.add_argument('--threads', default='1,4')
p.add_argument('--modes', default='xref,backward,entropy')
p.add_argument('--repeats', type=int, default=3)
p.add_argument('--budget-mb', type=int, default=8)
p.add_argument('--trace', type=Path)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--timeout', type=int, default=600)
p.add_argument('--reference', action='store_true', help='also measure in-memory xref with no build budget')
a = p.parse_args()
binary = a.binary.resolve()
report = {'machine': platform.platform(), 'python': platform.python_version(),
          'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
          'budget_mb': a.budget_mb, 'repeats': a.repeats, 'runs': [], 'summary': [],
          'cache_definition': 'cold removes persisted pass results; first dataset run also builds the private index; OS page cache is uncontrolled',
          'scope': 'real trace' if a.trace else 'synthetic trace (not evidence of real-workload speedup)'}
a.output.parent.mkdir(parents=True, exist_ok=True)
def save():
    temp = a.output.with_suffix('.tmp')
    temp.write_text(json.dumps(report, indent=2) + '\n')
    temp.replace(a.output)
def run(args):
    started = time.monotonic()
    r = subprocess.run([str(binary), *map(str, args)], text=True, capture_output=True, timeout=a.timeout)
    if r.returncode:
        raise RuntimeError(f'benchmark failed ({r.returncode}): {r.stderr[-4000:]} {r.stdout[-1000:]}')
    value = json.loads(r.stdout.strip().splitlines()[-1])
    value['wall_ms'] = (time.monotonic() - started) * 1000
    return value
with tempfile.TemporaryDirectory(prefix='retrace-scale-') as work:
    datasets = [(0, 'real', 0)] if a.trace else [(int(n), fmt, int(t)) for n in a.scales.split(',') for fmt in a.formats.split(',') for t in a.threads.split(',')]
    for n, fmt, threads in datasets:
        folder = Path(work) / f'{n}_{fmt}_{threads}'
        folder.mkdir()
        trace = folder / 'input.trace'
        if a.trace:
            try: os.link(a.trace.resolve(), trace)
            except OSError: shutil.copyfile(a.trace, trace)
        else:
            run(['--generate', n, '--threads', threads, '--format', fmt, '--output', trace])
        label = {'scale': n, 'format': fmt, 'threads': threads}
        for mode in a.modes.split(','):
            for cache in (['cold', 'warm'] if mode == 'xref' else ['cold']):
                measurements = []
                for repeat in range(a.repeats):
                    result = run(['--trace', trace, '--mode', mode, '--cache', cache, '--budget-mb', a.budget_mb])
                    result.update(label, repeat=repeat)
                    report['runs'].append(result); measurements.append(result)
                    print(json.dumps({**label, 'mode': mode, 'cache': cache, 'repeat': repeat,
                                      'pass_ms': round(result['pass_ms'], 2), 'rss_mb': round(result['peak_rss_mb'], 2)}), flush=True)
                    save()
                report['summary'].append({**label, 'mode': mode, 'cache': cache,
                    'median_pass_ms': statistics.median(x['pass_ms'] for x in measurements),
                    'peak_rss_mb': max(x['peak_rss_mb'] for x in measurements),
                    'index_bytes': max(x['index_bytes'] for x in measurements),
                    'first_run_index_ms': measurements[0]['index_ms'],
                    'cv': statistics.pstdev(x['pass_ms'] for x in measurements) / max(1e-9, statistics.mean(x['pass_ms'] for x in measurements))})
        if a.reference:
            result = run(['--trace', trace, '--mode', 'xref', '--cache', 'cold', '--reference', 'true'])
            result.update(label); report['runs'].append(result)
            print(json.dumps({**label, 'mode': 'xref_reference', 'pass_ms': result['pass_ms'], 'rss_mb': result['peak_rss_mb']}), flush=True)
        # Use a fresh cold query so a cache hit cannot hide cancellation latency.
        result = run(['--trace', trace, '--mode', 'xref', '--cache', 'cold', '--budget-mb', a.budget_mb, '--cancel-ms', '2'])
        result.update(label); report['runs'].append(result)
        save()
        shutil.rmtree(folder)
report['completed_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
save()
