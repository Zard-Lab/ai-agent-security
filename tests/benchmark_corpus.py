"""Labeled corpus for the guard precision/recall benchmark (see test_benchmark.py).

Each guard id maps to a list of labeled cases: a file (name + content) and whether
the guard SHOULD fire on it. `should_fire=True` = a true positive the guard must
catch; `should_fire=False` = a clean / FP-bait case the guard must stay silent on.

This is the quality ground-truth: extend it freely — more cases per guard sharpens
the measured precision (low false positives) and recall (low false negatives). It
deliberately reuses the same shapes as the per-guard unit tests, gathered here so we
get a single precision/recall number per guard instead of scattered asserts.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Case:
    name: str
    filename: str
    content: str
    should_fire: bool


CORPUS: dict[str, list[Case]] = {
    "command-injection": [
        Case("os.system f-string", "a.py", "import os\ndef f(h):\n    os.system(f'ping {h}')\n", True),
        Case("subprocess shell var", "b.py", "import subprocess\ndef f(c):\n    subprocess.run(c, shell=True)\n", True),
        Case("static literal", "c.py", "import os\nos.system('ls -la /tmp')\n", False),
        Case("array form (no shell)", "d.py", "import subprocess\ndef f(h):\n    subprocess.run(['ping', h])\n", False),
    ],
    "unsafe-deserialization": [
        Case("pickle.loads", "a.py", "import pickle\ndef f(b):\n    return pickle.loads(b)\n", True),
        Case("yaml.load unsafe", "b.py", "import yaml\nyaml.load(open('x').read())\n", True),
        Case("json.loads (safe)", "c.py", "import json\ndef f(s):\n    return json.loads(s)\n", False),
        Case("yaml.safe_load", "d.py", "import yaml\nyaml.safe_load(s)\n", False),
    ],
    "ssti": [
        Case("render_template_string concat", "a.py", "from flask import render_template_string\ndef p(n):\n    return render_template_string('Hi ' + n)\n", True),
        Case("autoescape=False", "b.py", "from jinja2 import Environment\nenv = Environment(autoescape=False)\n", True),
        Case("render_template (data)", "c.py", "from flask import render_template\ndef p(n):\n    return render_template('p.html', name=n)\n", False),
        Case("literal template", "d.py", "from flask import render_template_string\nrender_template_string('<p>hi</p>')\n", False),
    ],
    "path-traversal": [
        Case("send_file concat", "a.py", "from flask import send_file\ndef d(n):\n    return send_file('/data/' + n)\n", True),
        Case("open join var", "b.py", "import os\ndef r(n):\n    return open(os.path.join('/data', n)).read()\n", True),
        Case("static open", "c.py", "def r():\n    return open('config.toml').read()\n", False),
        Case("bare open(var)", "d.py", "def r(fh):\n    return open(fh).read()\n", False),
    ],
    "debug-default-off": [
        Case("DEBUG = True", "a.py", "DEBUG = True\n", True),
        Case("FastAPI(debug=True)", "b.py", "from fastapi import FastAPI\napp = FastAPI(debug=True)\n", True),
        Case("DEBUG = False", "c.py", "DEBUG = False\n", False),
        Case("env-driven", "d.py", "import os\nDEBUG = os.getenv('DEBUG', '') == '1'\n", False),
    ],
    "cors-wildcard": [
        Case("allow_origins=['*']", "a.py", "from fastapi.middleware.cors import CORSMiddleware\napp.add_middleware(CORSMiddleware, allow_origins=['*'])\n", True),
        Case("explicit origins", "b.py", "from fastapi.middleware.cors import CORSMiddleware\napp.add_middleware(CORSMiddleware, allow_origins=['https://app.example.com'])\n", False),
    ],
    "pg-ssl-required": [
        Case("remote DSN no ssl", "a.py", "DATABASE_URL = 'postgresql://app:pw@db.example.com:5432/app'\n", True),
        Case("sslmode=require", "b.py", "DATABASE_URL = 'postgresql://app:pw@db.example.com:5432/app?sslmode=require'\n", False),
        Case("localhost", "c.py", "DATABASE_URL = 'postgresql://app:pw@localhost:5432/app'\n", False),
    ],
    "jwt-alg": [
        Case("alg none", "a.py", "import jwt\ndef v(t):\n    return jwt.decode(t, 'k', algorithms=['none'])\n", True),
        Case("no algorithms=", "b.py", "import jwt\ndef v(t):\n    return jwt.decode(t, 'k')\n", True),
        Case("algorithms pinned", "c.py", "import jwt\ndef v(t):\n    return jwt.decode(t, 'k', algorithms=['HS256'])\n", False),
    ],
}
