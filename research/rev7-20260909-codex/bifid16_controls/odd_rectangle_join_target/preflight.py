#!/usr/bin/env python3
"""ASTRA hash/control preflight; never extracts canonical ciphertext."""
import importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
rt=load('astra_join_preflight_driver',HERE/'run_target.py');sc=load('astra_join_preflight_selection',HERE/'selection_controls.py');dc=load('astra_join_preflight_controls',HERE/'driver_controls.py')
rt.check_pins();assert json.loads((HERE/'selection_controls.json').read_text())==sc.build();assert dc.deterministic(json.loads((HERE/'driver_controls.json').read_text()))==dc.deterministic(dc.build())
assert not (HERE/'target_results.json').exists() and not (HERE/'target_results.json.tmp').exists()
print(json.dumps({'identity':'ASTRA','preflight':True,'target_evaluated':False,'canonical_ciphertext_extracted':False,'driver_sha256':rt.sha(HERE/'run_target.py'),'selection_ledger_sha256':rt.sha(HERE/'selection_controls.json'),'driver_controls_sha256':rt.sha(HERE/'driver_controls.json')},sort_keys=True))
