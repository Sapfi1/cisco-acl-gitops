import os
import re
import sqlite3
import ipaddress
import subprocess
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

REPO_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIGS_DIR = os.path.join(REPO_DIR, "configs")
DB_PATH = os.path.join(REPO_DIR, "cisco_acl.db")
# Автоматическая подготовка окружения Git и директорий
os.makedirs(CONFIGS_DIR, exist_ok=True)
if not os.path.exists(os.path.join(REPO_DIR, ".git")):
    subprocess.run(["git", "config", "--global", "--add", "safe.directory", "*"], check=False)
    subprocess.run(["git", "init", REPO_DIR], check=True

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS acls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            acl_name TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(hostname, acl_name)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            acl_id INTEGER,
            seq TEXT,
            action TEXT,
            protocol TEXT,
            src TEXT,
            src_remark TEXT,
            dst TEXT,
            dst_remark TEXT,
            port TEXT,
            ticket_id TEXT,
            security_approver TEXT,
            status TEXT DEFAULT 'Active',
            FOREIGN KEY (acl_id) REFERENCES acls (id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

RU_TO_EN = {
    'а':'a','б':'b','в':'v','г':'g','д':'d','е':'e','ё':'e','ж':'zh','з':'z','и':'i','й':'y',
    'к':'k','л':'l','м':'m','н':'n','о':'o','п':'p','р':'r','с':'s','т':'t','у':'u','ф':'f',
    'х':'kh','ц':'ts','ч':'ch','ш':'sh','щ':'shch','ъ':'','ы':'y','ь':'','э':'e','ю':'yu','я':'ya',
    'А':'A','Б':'B','В':'V','Г':'G','Д':'D','Е':'E','Ё':'E','Ж':'Zh','З':'Z','И':'I','Й':'Y',
    'К':'K','Л':'L','М':'M','Н':'N','О':'O','П':'P','Р':'R','С':'S','Т':'T','У':'U','Ф':'F',
    'Х':'Kh','Ц':'Ts','Ч':'Ch','Ш':'Sh','Щ':'Shch','Ъ':'','Ы':'Y','Ь':'','Э':'E','Ю':'Yu','Я':'Ya'
}

def transliterate(text: str) -> str:
    if not text: return ""
    clean = "".join(RU_TO_EN.get(c, c) for c in text)
    return re.sub(r'[^a-zA-Z0-9_\-\.\:\s\[\]\>]', '', clean).strip()

def is_valid_ipv4(ip_str: str) -> bool:
    try:
        ipaddress.IPv4Address(ip_str.strip())
        return True
    except ValueError:
        return False

def parse_network_target(val: str) -> str:
    val = val.strip()
    if not val or val.lower() == 'any': return 'any'
    parts = val.split()
    if len(parts) == 2:
        ip_part, wc_part = parts[0], parts[1]
        wc_octets = wc_part.split('.')
        if is_valid_ipv4(ip_part) and len(wc_octets) == 4:
            if all(o.isdigit() and 0 <= int(o) <= 255 for o in wc_octets):
                if wc_part == '0.0.0.0': return f"host {ip_part}"
                elif wc_part == '255.255.255.255': return "any"
                return f"{ip_part} {wc_part}"
    cidr_val = val if '/' in val else f"{val}/32"
    try:
        net = ipaddress.ip_network(cidr_val, strict=False)
        if net.prefixlen == 32: return f"host {net.network_address}"
        elif net.prefixlen == 0: return "any"
        return f"{net.network_address} {net.hostmask}"
    except ValueError:
        return val

def parse_cisco_tokens_to_ui(tokens: list):
    if not tokens: return 'any', 0
    if tokens[0] == 'any': return 'any', 1
    if tokens[0] == 'host' and len(tokens) > 1: return f"{tokens[1]}/32", 2
    if len(tokens) >= 2 and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', tokens[1]):
        return f"{tokens[0]} {tokens[1]}", 2
    return tokens[0], 1

def parse_cisco_acl_to_rules(raw_cli: str):
    rules = []
    lines = raw_cli.strip().splitlines()
    pending_ticket = ""
    pending_src_remark = ""
    pending_dst_remark = ""

    for line in lines:
        line = line.strip()
        if not line or line.startswith('!') or line.startswith('ip access-list'): continue
        tokens = line.split()

        if 'remark' in tokens:
            rem_idx = tokens.index('remark')
            rem_text = " ".join(tokens[rem_idx + 1:])
            parts = rem_text.split("->")
            for p in parts:
                p = p.strip()
                if p.startswith("TICKET:"): pending_ticket = p.replace("TICKET:", "").strip()
                elif p.startswith("SRC:"): pending_src_remark = p.replace("SRC:", "").strip()
                elif p.startswith("DST:"): pending_dst_remark = p.replace("DST:", "").strip()
                elif not ":" in p and not pending_src_remark: pending_src_remark = p
            continue

        seq = ""
        if tokens and tokens[0].isdigit(): seq = tokens.pop(0)
        if not tokens: continue
        action = tokens.pop(0) if tokens[0] in ['permit', 'deny'] else 'permit'
        proto = tokens.pop(0) if tokens else 'ip'
        if proto not in ['ip', 'tcp', 'udp', 'icmp']: proto = 'ip'

        src_val, consumed = parse_cisco_tokens_to_ui(tokens)
        tokens = tokens[consumed:]
        if tokens and tokens[0] in ['eq', 'range', 'gt', 'lt', 'neq']:
            tokens = tokens[3:] if tokens[0] == 'range' else tokens[2:]

        dst_val, consumed = parse_cisco_tokens_to_ui(tokens)
        tokens = tokens[consumed:]

        dst_port = ""
        if tokens and tokens[0] in ['eq', 'range']:
            op = tokens.pop(0)
            if op == 'eq' and tokens: dst_port = tokens.pop(0)
            elif op == 'range' and len(tokens) >= 2: dst_port = f"{tokens.pop(0)}-{tokens.pop(0)}"

        rules.append({
            "seq": seq, "action": action, "protocol": proto,
            "src": src_val, "src_remark": pending_src_remark,
            "dst": dst_val, "dst_remark": pending_dst_remark,
            "port": dst_port, "ticket_id": pending_ticket, "security_approver": "Системный импорт", "status": "Active"
        })
        pending_ticket = ""; pending_src_remark = ""; pending_dst_remark = ""
    return rules

def build_raw_commands(acl_name: str, rules: list) -> str:
    raw_lines = [f"ip access-list extended {acl_name}"]
    for rule in rules:
        seq = str(rule.get('seq', '')).strip()
        action = rule.get('action', 'permit')
        protocol = rule.get('protocol', 'ip')
        src_raw = rule.get('src', 'any')
        dst_raw = rule.get('dst', 'any')
        src_remark = transliterate(rule.get('src_remark', '').strip())
        dst_remark = transliterate(rule.get('dst_remark', '').strip())
        port_raw = str(rule.get('port', '')).strip()
        ticket_id = rule.get('ticket_id', '').strip()

        remark_parts = []
        if ticket_id: remark_parts.append(f"TICKET:{ticket_id}")
        if src_remark: remark_parts.append(f"SRC:{src_remark}")
        if dst_remark: remark_parts.append(f"DST:{dst_remark}")

        if remark_parts:
            raw_lines.append(f" remark {' -> '.join(remark_parts)}")

        src_str = parse_network_target(src_raw)
        dst_str = parse_network_target(dst_raw)

        port_str = ""
        if protocol in ['tcp', 'udp'] and port_raw and port_raw.lower() != 'any':
            port_parts = re.split(r'[\s\-]+', port_raw)
            if len(port_parts) >= 2: port_str = f" range {port_parts[0]} {port_parts[1]}"
            else: port_str = f" eq {port_parts[0]}"

        seq_prefix = f"{seq} " if seq and seq.isdigit() else ""
        raw_lines.append(f" {seq_prefix}{action} {protocol} {src_str} {dst_str}{port_str}")

    return "\n".join(raw_lines)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cisco ACL GitOps & Security Compliance</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body { background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 25px 0; }
        .card { border: none; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.06); margin-bottom: 25px; }
        .table th { background-color: #f8fafc; font-size: 0.70rem; text-transform: uppercase; color: #475569; font-weight: 700; border-bottom: 2px solid #e2e8f0; vertical-align: middle; text-align: center; }
        .btn-generate { background-color: #2563eb; color: white; font-weight: 700; text-transform: uppercase; padding: 10px; border: none; border-radius: 6px; }
        .btn-generate:hover { background-color: #1d4ed8; color: white; }
        .btn-deploy { background-color: #e11d48; color: white; font-weight: 700; text-transform: uppercase; padding: 12px; border: none; border-radius: 6px; }
        .btn-deploy:hover { background-color: #be123c; color: white; }
        .terminal-container { position: relative; }
        .terminal { background-color: #0f172a; color: #38bdf8; font-family: 'Consolas', monospace; padding: 20px; border-radius: 8px; font-size: 13px; white-space: pre-wrap; min-height: 140px; }
        .btn-copy { position: absolute; top: 12px; right: 12px; z-index: 10; font-size: 12px; }
        .seq-input { text-align: center; font-weight: 600; color: #1e3a8a; }
        .step-badge { background-color: #e2e8f0; color: #334155; font-weight: bold; border-radius: 50%; width: 22px; height: 22px; display: inline-flex; align-items: center; justify-content: center; font-size: 12px; margin-right: 6px; }
    </style>
</head>
<body>

<div class="container-fluid px-4">
    <!-- Блок конструктора -->
    <div class="card p-4">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="m-0 fw-bold text-primary">
                <i class="fa-solid fa-shield-halved me-2"></i>Cisco ACL Конструктор с контролем ИБ
            </h5>
            <span class="badge bg-dark">База данных SQLite + GitLab CI</span>
        </div>

        <div class="row g-3 p-3 mb-4 align-items-end" style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px;">
            <div class="col-md-4">
                <label class="form-label small fw-bold text-secondary"><span class="step-badge">1</span>Коммутатор:</label>
                <div class="input-group input-group-sm">
                    <input type="text" class="form-control" id="hostname" value="switch">
                    <button class="btn btn-outline-dark fw-bold" id="btn_get_names" onclick="fetchAclNames()">
                        <i class="fa-solid fa-list-ul me-1"></i> Найти ACL
                    </button>
                </div>
            </div>
            <div class="col-md-5">
                <label class="form-label small fw-bold text-secondary"><span class="step-badge">2</span>Имя Access-листа:</label>
                <div class="input-group input-group-sm">
                    <input type="text" class="form-control" id="acl_name_input" value="acl" placeholder="Введите имя ACL">
                    <button class="btn btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">Список</button>
                    <ul class="dropdown-menu dropdown-menu-end" id="acl_dropdown">
                        <li><a class="dropdown-item" href="#" onclick="setAclName('acl')">acl</a></li>
                    </ul>
                    <button class="btn btn-outline-primary fw-bold" id="btn_get_db" onclick="loadRulesFromDBOrSwitch()">
                        <i class="fa-solid fa-database me-1"></i> Загрузить из БД
                    </button>
                </div>
            </div>
            <div class="col-md-3 text-end">
                <button class="btn btn-outline-dark btn-sm fw-bold" onclick="fetchAclRules()">
                    <i class="fa-solid fa-download me-1"></i> Опросить свитч
                </button>
            </div>
        </div>

        <div class="table-responsive">
            <table class="table table-bordered align-middle" id="acl_table">
                <thead>
                    <tr>
                        <th style="width: 5%;">№ (10, 20...)</th>
                        <th style="width: 7%;">Действие</th>
                        <th style="width: 7%;">Протокол</th>
                        <th style="width: 14%;">Источник</th>
                        <th style="width: 11%;">Описание источнику</th>
                        <th style="width: 14%;">Назначение</th>
                        <th style="width: 11%;">Описание назначения</th>
                        <th style="width: 10%;">Порт</th>
                        <th style="width: 10%;">Тикет (ИБ)</th>
                        <th style="width: 11%;">Согласующий ИБ</th>
                        <th style="width: 3%;">✖</th>
                    </tr>
                </thead>
                <tbody id="rules_body"></tbody>
            </table>
        </div>

        <div class="mb-4">
            <button class="btn btn-success btn-sm" onclick="addNewRow()"><i class="fa-solid fa-plus me-1"></i> Добавить строку</button>
        </div>

        <div class="row g-2 mb-3">
            <div class="col-md-8">
                <button class="btn btn-generate w-100" onclick="generateConfig(false)">
                    <i class="fa-solid fa-terminal me-2"></i> Сформировать конфигурацию в БД
                </button>
            </div>
            <div class="col-md-4">
                <button class="btn btn-outline-primary fw-bold w-100 p-2" onclick="generateConfig(true)">
                    <i class="fa-solid fa-download me-2"></i> Скачать .txt
                </button>
            </div>
        </div>

        <div class="mb-4">
            <button class="btn btn-deploy w-100" id="btn_deploy" onclick="deployToGitLab()">
                <i class="fa-solid fa-cloud-arrow-up me-2"></i> <span id="deploy_text">Зафиксировать в БД, Git и запустить GitLab деплой</span>
            </button>
        </div>

        <div>
            <h6 class="fw-bold text-secondary m-0 mb-1">Сгенерированный конфиг:</h6>
            <div class="terminal-container">
                <button class="btn btn-sm btn-outline-light btn-copy" onclick="copyToClipboard()"><i class="fa-regular fa-copy me-1"></i> Копировать</button>
                <pre class="terminal" id="output_box">Ожидание действий...</pre>
            </div>
        </div>
    </div>

    <!-- Блок истории и аудита из БД -->
    <div class="card p-4">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h5 class="m-0 fw-bold text-secondary">
                <i class="fa-solid fa-clock-rotate-left me-2"></i>Журнал учета и аудита (Сохраненные правила в SQLite)
            </h5>
            <button class="btn btn-outline-secondary btn-sm" onclick="loadAuditHistory()">
                <i class="fa-solid fa-rotate me-1"></i> Обновить журнал
            </button>
        </div>
        <div class="table-responsive">
            <table class="table table-striped table-bordered align-middle" id="audit_table">
                <thead>
                    <tr>
                        <th>Хост</th>
                        <th>ACL</th>
                        <th>№</th>
                        <th>Действие</th>
                        <th>Протокол</th>
                        <th>Источник</th>
                        <th>Назначение</th>
                        <th>Порт</th>
                        <th>Тикет (ИБ)</th>
                        <th>Согласующий ИБ</th>
                        <th>Статус</th>
                    </tr>
                </thead>
                <tbody id="audit_body">
                    <!-- Заполняется через JS -->
                </tbody>
            </table>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
    let latestRawConfig = "";

    function setAclName(name) {
        document.getElementById('acl_name_input').value = name;
        loadRulesFromDBOrSwitch();
    }

    function setupRowEvents(row) {
        const protoSelect = row.querySelector('.proto-select');
        const portInput = row.querySelector('.dst-port');
        protoSelect.addEventListener('change', () => {
            const proto = protoSelect.value;
            if (proto === 'tcp' || proto === 'udp') {
                portInput.disabled = false;
                portInput.classList.remove('bg-light', 'text-muted');
                if (portInput.value === 'any') portInput.value = '';
            } else {
                portInput.disabled = true;
                portInput.classList.add('bg-light', 'text-muted');
                portInput.value = 'any';
            }
        });
    }

    function createRowElement(rule = {}) {
        const tr = document.createElement('tr');
        tr.className = 'rule-row';
        const currentProto = rule.protocol || 'ip';
        const isPortDisabled = (currentProto !== 'tcp' && currentProto !== 'udp');

        tr.innerHTML = `
            <td><input type="text" class="form-control form-control-sm seq-input" value="${rule.seq || ''}" placeholder="10"></td>
            <td>
                <select class="form-select form-select-sm action-select">
                    <option value="permit" ${rule.action === 'permit' ? 'selected' : ''}>permit</option>
                    <option value="deny" ${rule.action === 'deny' ? 'selected' : ''}>deny</option>
                </select>
            </td>
            <td>
                <select class="form-select form-select-sm proto-select">
                    <option value="ip" ${currentProto === 'ip' ? 'selected' : ''}>ip</option>
                    <option value="tcp" ${currentProto === 'tcp' ? 'selected' : ''}>tcp</option>
                    <option value="udp" ${currentProto === 'udp' ? 'selected' : ''}>udp</option>
                    <option value="icmp" ${currentProto === 'icmp' ? 'selected' : ''}>icmp</option>
                </select>
            </td>
            <td><input type="text" class="form-control form-control-sm src-ip" value="${rule.src || 'any'}" placeholder="any"></td>
            <td><input type="text" class="form-control form-control-sm src-remark" value="${rule.src_remark || ''}" placeholder="Источник"></td>
            <td><input type="text" class="form-control form-control-sm dst-ip" value="${rule.dst || 'any'}" placeholder="any"></td>
            <td><input type="text" class="form-control form-control-sm dst-remark" value="${rule.dst_remark || ''}" placeholder="Назначение"></td>
            <td><input type="text" class="form-control form-control-sm dst-port ${isPortDisabled ? 'bg-light text-muted' : ''}" value="${rule.port || (isPortDisabled ? 'any' : '')}" ${isPortDisabled ? 'disabled' : ''} placeholder="80"></td>
            <td><input type="text" class="form-control form-control-sm ticket-input" value="${rule.ticket_id || ''}" placeholder="JIRA-123"></td>
            <td><input type="text" class="form-control form-control-sm approver-input" value="${rule.security_approver || ''}" placeholder="Иванов И.И."></td>
            <td class="text-center"><button class="btn btn-outline-danger btn-sm p-1 px-2" onclick="removeRow(this)"><i class="fa-solid fa-xmark"></i></button></td>
        `;
        setupRowEvents(tr);
        return tr;
    }

    function addNewRow() {
        const rows = document.querySelectorAll('.rule-row');
        let nextSeq = "10";
        if (rows.length > 0) {
            const lastSeqVal = rows[rows.length - 1].querySelector('.seq-input').value.trim();
            if (!isNaN(lastSeqVal) && lastSeqVal !== "") {
                nextSeq = String(parseInt(lastSeqVal) + 10);
            }
        }
        const newRow = createRowElement({ protocol: 'ip', seq: nextSeq });
        document.getElementById('rules_body').appendChild(newRow);
    }

    function removeRow(btn) {
        if (document.querySelectorAll('.rule-row').length > 1) {
            btn.closest('tr').remove();
        }
    }

    function collectCurrentRules() {
        const rules = [];
        document.querySelectorAll('.rule-row').forEach(r => {
            rules.push({
                seq: r.querySelector('.seq-input').value.trim(),
                action: r.querySelector('.action-select').value,
                protocol: r.querySelector('.proto-select').value,
                src: r.querySelector('.src-ip').value,
                dst: r.querySelector('.dst-ip').value,
                src_remark: r.querySelector('.src-remark').value,
                dst_remark: r.querySelector('.dst-remark').value,
                port: r.querySelector('.dst-port').value,
                ticket_id: r.querySelector('.ticket-input').value.trim(),
                security_approver: r.querySelector('.approver-input').value.trim()
            });
        });
        return rules;
    }

    async function fetchAclNames() {
            const hostname = document.getElementById('hostname').value.trim() || 'switch';
            const res = await fetch('/api/get_acl_names', {
                method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ hostname })
            });
            const data = await res.json();
            const dropdown = document.getElementById('acl_dropdown');
            dropdown.innerHTML = '';
        
            if (data.status === 'success' && data.acls && data.acls.length > 0) {
                data.acls.forEach(name => {
                    const li = document.createElement('li');
                    const a = document.createElement('a');
                    a.className = 'dropdown-item';
                    a.href = '#';
                    a.textContent = name;
                    a.onclick = (e) => {
                        e.preventDefault();
                        setAclName(name);
                    };
                    li.appendChild(a);
                    dropdown.appendChild(li);
                });
            } else {
                const li = document.createElement('li');
                const a = document.createElement('a');
                a.className = 'dropdown-item';
                a.href = '#';
                a.textContent = 'acl';
                a.onclick = (e) => {
                    e.preventDefault();
                    setAclName('acl');
                };
                li.appendChild(a);
                dropdown.appendChild(li);
            }
        }

    async function loadRulesFromDBOrSwitch() {
            const hostname = document.getElementById('hostname').value.trim() || 'switch';
            const aclName = document.getElementById('acl_name_input').value.trim() || 'acl';
        
            try {
                const res = await fetch('/api/get_db_rules', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ hostname, acl_name: aclName })
                });
                const data = await res.json();
                const tbody = document.getElementById('rules_body');
                tbody.innerHTML = '';

                if (data.status === 'success' && data.rules && data.rules.length > 0) {
                    data.rules.forEach(r => tbody.appendChild(createRowElement(r)));
                    generateConfig(false);
                } else {
                    // Если в базе ничего нет — обязательно создаем пустую строку для ввода!
                    addNewRow();
                }
            } catch(e) {
                console.error('Ошибка загрузки из БД', e);
                addNewRow();
            }
        }

    async function fetchAclRules() {
        const hostname = document.getElementById('hostname').value.trim() || 'switch';
        const aclName = document.getElementById('acl_name_input').value.trim() || 'acl';
        const res = await fetch('/api/fetch_from_switch', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ hostname, acl_name: aclName })
        });
        const data = await res.json();
        if (data.status === 'success') {
            const tbody = document.getElementById('rules_body');
            tbody.innerHTML = '';
            if (data.rules.length === 0) addNewRow();
            else data.rules.forEach(r => tbody.appendChild(createRowElement(r)));
            document.getElementById('output_box').textContent = data.raw_cisco;
        }
    }

    async function generateConfig(triggerDownload = false) {
        const rules = collectCurrentRules();
        const aclName = document.getElementById('acl_name_input').value.trim() || 'acl';
        const res = await fetch('/generate', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ acl_name: aclName, rules })
        });
        const data = await res.json();
        latestRawConfig = data.config_raw;
        document.getElementById('output_box').textContent = latestRawConfig;

        if (triggerDownload && latestRawConfig) {
            const blob = new Blob([latestRawConfig], { type: 'text/plain;charset=utf-8' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url; a.download = `${aclName}.txt`;
            document.body.appendChild(a); a.click(); a.remove();
        }
    }

    async function deployToGitLab() {
        const hostname = document.getElementById('hostname').value.trim() || 'switch';
        const aclName = document.getElementById('acl_name_input').value.trim() || 'acl';
        const rules = collectCurrentRules();

        if (!confirm(`Сохранить изменения в БД SQLite, зафиксировать в Git и запустить деплой для ${aclName}?`)) return;

        const res = await fetch('/api/deploy_to_gitlab', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ hostname, acl_name: aclName, rules })
        });
        const data = await res.json();
        if (data.status === 'success') {
            alert('Успешно! Данные записаны в БД, коммит отправлен в Git.');
            loadAuditHistory();
        } else {
            alert('Ошибка: ' + data.error);
        }
    }

    async function loadAuditHistory() {
        try {
            const res = await fetch('/api/audit_history');
            const data = await res.json();
            const tbody = document.getElementById('audit_body');
            tbody.innerHTML = '';
            if (data.status === 'success' && data.history.length > 0) {
                data.history.forEach(item => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td class="fw-bold">${item.hostname}</td>
                        <td>${item.acl_name}</td>
                        <td class="text-center"><code>${item.seq || '-'}</code></td>
                        <td><span class="badge ${item.action === 'permit' ? 'bg-success' : 'bg-danger'}">${item.action}</span></td>
                        <td><code>${item.protocol}</code></td>
                        <td>${item.src}</td>
                        <td>${item.dst}</td>
                        <td>${item.port || '-'}</td>
                        <td class="fw-bold text-primary">${item.ticket_id || 'Нет тикета'}</td>
                        <td>${item.security_approver || 'Не указан'}</td>
                        <td><span class="badge bg-secondary">${item.status}</span></td>
                    `;
                    tbody.appendChild(tr);
                });
            } else {
                tbody.innerHTML = '<tr><td colspan="11" class="text-center text-muted">Журнал базы данных пуст</td></tr>';
            }
        } catch(e) {
            console.error('Ошибка загрузки аудита');
        }
    }

    function copyToClipboard() {
        if (!latestRawConfig) return;
        navigator.clipboard.writeText(latestRawConfig).then(() => {
            alert('Скопировано в буфер обмена');
        });
    }

    // Гарантированный запуск только после полного построения страницы
        document.addEventListener("DOMContentLoaded", () => {
            loadRulesFromDBOrSwitch();
            loadAuditHistory();
        });
    // Автоматическая загрузка при старте
    //loadRulesFromDBOrSwitch();
    //loadAuditHistory();
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/get_acl_names', methods=['POST'])
def get_acl_names():
    data = request.json or {}
    hostname = data.get('hostname', 'switch').strip() or 'switch'
    cmd = ["ansible-playbook", "-i", "inventory/hosts.yaml", "playbooks/cisco_acl_ops.yml", "--extra-vars", f"target_host={hostname} action=get_names"]
    try:
        proc = subprocess.run(cmd, cwd=REPO_DIR, capture_output=True, text=True, timeout=30)
        match = re.search(r'"msg": "(.*?)"', proc.stdout, re.DOTALL)
        raw_msg = match.group(1).encode().decode('unicode_escape') if match else ""
        acl_names = sorted(list(set(re.findall(r'ip access-list (?:extended|standard) (\S+)', raw_msg))))
        return jsonify({"status": "success", "acls": acl_names})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})

@app.route('/api/get_db_rules', methods=['POST'])
def get_db_rules():
    data = request.json or {}
    hostname = data.get('hostname', 'switch').strip() or 'switch'
    acl_name = data.get('acl_name', 'acl').strip() or 'acl'
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT r.* FROM rules r
            JOIN acls a ON r.acl_id = a.id
            WHERE a.hostname = ? AND a.acl_name = ?
            ORDER BY r.id ASC
        ''', (hostname, acl_name))
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({"status": "success", "rules": rows})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/api/fetch_from_switch', methods=['POST'])
def fetch_from_switch():
    data = request.json or {}
    hostname = data.get('hostname', 'switch').strip() or 'switch'
    acl_name = data.get('acl_name', 'acl').strip() or 'acl'
    cmd = ["ansible-playbook", "-i", "inventory/hosts.yaml", "playbooks/cisco_acl_ops.yml", "--extra-vars", f"target_host={hostname} action=get_rules acl_name={acl_name}"]
    try:
        proc = subprocess.run(cmd, cwd=REPO_DIR, capture_output=True, text=True, timeout=30)
        match = re.search(r'"msg": "(.*?)"', proc.stdout, re.DOTALL)
        raw_cisco = match.group(1).encode().decode('unicode_escape') if match else ""
        rules = parse_cisco_acl_to_rules(raw_cisco)
        return jsonify({"status": "success", "raw_cisco": raw_cisco, "rules": rules})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)})

@app.route('/generate', methods=['POST'])
def generate():
    data = request.json or {}
    acl_name = data.get('acl_name', 'acl').strip() or 'acl'
    rules = data.get('rules', [])
    commands = build_raw_commands(acl_name, rules)
    return jsonify({"config_raw": f"configure terminal\n{commands}\nexit\nwrite memory\n"})

@app.route('/api/audit_history', methods=['GET'])
def audit_history():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT a.hostname, a.acl_name, r.seq, r.action, r.protocol, r.src, r.dst, r.port, r.ticket_id, r.security_approver, r.status
            FROM rules r
            JOIN acls a ON r.acl_id = a.id
            ORDER BY a.updated_at DESC, r.id ASC
        ''')
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({"status": "success", "history": rows})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/api/deploy_to_gitlab', methods=['POST'])
def deploy_to_gitlab():
    data = request.json or {}
    hostname = data.get('hostname', 'switch').strip() or 'switch'
    acl_name = data.get('acl_name', 'acl').strip() or 'acl'
    rules = data.get('rules', [])

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('INSERT OR IGNORE INTO acls (hostname, acl_name) VALUES (?, ?)', (hostname, acl_name))
        cursor.execute('SELECT id FROM acls WHERE hostname = ? AND acl_name = ?', (hostname, acl_name))
        acl_id = cursor.fetchone()[0]

        cursor.execute('DELETE FROM rules WHERE acl_id = ?', (acl_id,))
        for r in rules:
            cursor.execute('''
                INSERT INTO rules (acl_id, seq, action, protocol, src, src_remark, dst, dst_remark, port, ticket_id, security_approver, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                acl_id, r.get('seq'), r.get('action'), r.get('protocol'),
                r.get('src'), r.get('src_remark'), r.get('dst'), r.get('dst_remark'),
                r.get('port'), r.get('ticket_id'), r.get('security_approver'), 'Active'
            ))
        conn.commit()
        conn.close()
    except Exception as e:
        return jsonify({"status": "error", "error": f"DB Error: {str(e)}"}), 500

    raw_config = build_raw_commands(acl_name, rules)
    cfg_filename = f"{hostname}_{acl_name}.cfg"
    cfg_filepath = os.path.join(CONFIGS_DIR, cfg_filename)

    try:
        with open(cfg_filepath, "w", encoding="utf-8") as f:
            f.write(raw_config + "\n")

        subprocess.run(["git", "config", "user.name", "ACL Bot"], cwd=REPO_DIR, check=True)
        subprocess.run(["git", "config", "user.email", "bot@local"], cwd=REPO_DIR, check=True)
        subprocess.run(["git", "add", f"configs/{cfg_filename}"], cwd=REPO_DIR, check=True)

        diff_check = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=REPO_DIR)
        if diff_check.returncode != 0:
            commit_msg = f"[ACL-UPDATE] {acl_name} on {hostname} (DB updated)"
            subprocess.run(["git", "commit", "-m", commit_msg], cwd=REPO_DIR, check=True)

        return jsonify({"status": "success", "message": "Данные сохранены в БД и Git."})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
