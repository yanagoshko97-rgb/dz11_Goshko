import hashlib
import os
import time
from datetime import datetime

import mysql.connector
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

HASH_SECRET = "hash_secret_demo"

DEMO_COMPONENTS = [
    {
        "component_id": "cfg_app",
        "component_type": "config",
        "content": "database.host=localhost",
        "reference_content": "database.host=localhost",
        "checked_at": "01.05.2026 00:00:00",
    },
    {
        "component_id": "bin_worker",
        "component_type": "binary",
        "content": "worker_start_hacked",
        "reference_content": "worker_start",
        "checked_at": "01.05.2026 00:00:00",
    },
    {
        "component_id": "lib_crypto",
        "component_type": "library",
        "content": "encrypt_function",
        "reference_content": "encrypt_function",
        "checked_at": "01.05.2026 00:00:00",
    },
    {
        "component_id": "cfg_security",
        "component_type": "config",
        "content": "auth=false",
        "reference_content": "auth=true",
        "checked_at": "01.05.2026 00:00:00",
    },
]

SECURITY_EVENTS = []


def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host="mysql",
            user="root",
            password="root",
            database="integrity_db",
            port=3306
        )
        return connection
    except Exception:
        raise RuntimeError("Не удалось подключиться к MySQL")


def compute_hash(text):
    return hashlib.sha256((text + HASH_SECRET).encode("utf-8")).hexdigest()


def init_db():
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS integrity_checks (
            id INT AUTO_INCREMENT PRIMARY KEY,
            component_id VARCHAR(100),
            component_type VARCHAR(100),
            content TEXT,
            reference_content TEXT,
            current_hash VARCHAR(128),
            reference_hash VARCHAR(128),
            status VARCHAR(50),
            checked_at DATETIME
        )
    """)

    connection.commit()
    cursor.close()
    connection.close()


def check_component(component):
    current_hash = compute_hash(component["content"])
    reference_hash = compute_hash(component["reference_content"])
    hash_ok = current_hash == reference_hash

    return {
        "component_id": component["component_id"],
        "component_type": component["component_type"],
        "content": component["content"],
        "reference_content": component["reference_content"],
        "current_hash": current_hash,
        "reference_hash": reference_hash,
        "hash_ok": hash_ok,
        "status": "OK" if hash_ok else "HASH_MISMATCH",
        "checked_at": component["checked_at"],
    }


def save_component_to_db(component):
    checked = check_component(component)

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO integrity_checks
        (component_id, component_type, content, reference_content,
         current_hash, reference_hash, status, checked_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        checked["component_id"],
        checked["component_type"],
        checked["content"],
        checked["reference_content"],
        checked["current_hash"],
        checked["reference_hash"],
        checked["status"],
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    ))

    connection.commit()
    cursor.close()
    connection.close()


def load_components_from_db():
    init_db()

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT component_id, component_type, content, reference_content, checked_at
        FROM integrity_checks
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    cursor.close()
    connection.close()

    components = []

    for row in rows:
        checked_at = row["checked_at"]
        if hasattr(checked_at, "strftime"):
            checked_at = checked_at.strftime("%d.%m.%Y %H:%M:%S")

        components.append({
            "component_id": row["component_id"],
            "component_type": row["component_type"],
            "content": row["content"],
            "reference_content": row["reference_content"],
            "checked_at": checked_at,
        })

    return components


def get_security_info():
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
    is_secure = request.is_secure or forwarded_proto == "https"

    if is_secure:
        return "HTTPS", "Безопасно", "Защищенное соединение активно"

    return "HTTP", "Требуется внимание", "Соединение не защищено"


PAGE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Контейнер контроля целостности компонентов</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #f4f6f8;
            color: #222;
        }

        header {
            background: #17212b;
            color: white;
            padding: 25px;
            text-align: center;
        }

        .container {
            width: 95%;
            max-width: 1200px;
            margin: 25px auto;
        }

        .cards {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            margin-bottom: 25px;
        }

        .card {
            flex: 1;
            min-width: 200px;
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        .card h2 {
            margin: 0;
            font-size: 18px;
            color: #555;
        }

        .number {
            margin-top: 12px;
            font-size: 32px;
            font-weight: bold;
        }

        .ok { color: #188038; }
        .fail { color: #d93025; }
        .blue { color: #0b57d0; }

        .section {
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        .security-section {
            border-left: 6px solid #0b57d0;
        }

        .charts {
            display: flex;
            gap: 25px;
            flex-wrap: wrap;
        }

        .chart-box {
            flex: 1;
            min-width: 300px;
        }

        canvas {
            max-height: 320px;
        }

        form {
            display: grid;
            gap: 12px;
        }

        label {
            font-weight: bold;
        }

        input, select, textarea {
            width: 100%;
            padding: 10px;
            border: 1px solid #ccd3da;
            border-radius: 8px;
            font-size: 14px;
            box-sizing: border-box;
        }

        textarea {
            min-height: 80px;
            resize: vertical;
        }

        button {
            background: #0b57d0;
            color: white;
            border: none;
            padding: 12px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 15px;
            font-weight: bold;
        }

        button:hover {
            background: #0842a0;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 14px;
        }

        th {
            background: #17212b;
            color: white;
            padding: 10px;
        }

        td {
            border-bottom: 1px solid #ddd;
            padding: 10px;
            vertical-align: top;
        }

        tr:hover {
            background: #f1f5f9;
        }

        .hash {
            font-family: monospace;
            font-size: 11px;
            word-break: break-all;
        }

        .badge-ok {
            background: #dff5e5;
            color: #188038;
            padding: 5px 8px;
            border-radius: 8px;
            font-weight: bold;
        }

        .badge-fail {
            background: #fde7e7;
            color: #d93025;
            padding: 5px 8px;
            border-radius: 8px;
            font-weight: bold;
        }

        .badge-warning {
            background: #fff4d6;
            color: #8a5a00;
            padding: 5px 8px;
            border-radius: 8px;
            font-weight: bold;
        }
    </style>
</head>

<body>

<header>
    <h1>Контейнер контроля целостности компонентов автоматизированной системы</h1>
    <p>Проверка целостности компонентов и мониторинг защищенного режима доступа</p>
</header>

<div class="container">

    <div class="cards">
        <div class="card">
            <h2>Всего компонентов</h2>
            <div class="number">{{ total }}</div>
        </div>

        <div class="card">
            <h2>Целостность подтверждена</h2>
            <div class="number ok">{{ ok_count }}</div>
            <p>{{ ok_percent }}%</p>
        </div>

        <div class="card">
            <h2>Нарушения</h2>
            <div class="number fail">{{ fail_count }}</div>
            <p>{{ fail_percent }}%</p>
        </div>
    </div>

    <div class="section security-section">
        <h2>Модуль контроля защищенного режима</h2>

        <div class="cards">
            <div class="card">
                <h2>Текущий протокол</h2>
                <div class="number blue">{{ protocol_status }}</div>
            </div>

            <div class="card">
                <h2>Уровень защищенности</h2>
                {% if protocol_status == "HTTPS" %}
                    <div class="number ok">{{ security_level }}</div>
                {% else %}
                    <div class="number fail">{{ security_level }}</div>
                {% endif %}
                <p>{{ security_message }}</p>
            </div>

            <div class="card">
                <h2>Проверок соединения</h2>
                <div class="number">{{ security_checks_total }}</div>
            </div>
        </div>

        <div class="charts">
            <div class="chart-box">
                <h3>Диаграмма обращений HTTP/HTTPS</h3>
                <canvas id="securityChart"></canvas>
            </div>

            <div class="chart-box">
                <h3>Журнал событий защищенного режима</h3>

                <table>
                    <thead>
                        <tr>
                            <th>Время</th>
                            <th>Протокол</th>
                            <th>Уровень</th>
                            <th>Сообщение</th>
                        </tr>
                    </thead>

                    <tbody>
                        {% for event in security_events %}
                        <tr>
                            <td>{{ event.time }}</td>
                            <td>
                                {% if event.protocol == "HTTPS" %}
                                    <span class="badge-ok">{{ event.protocol }}</span>
                                {% else %}
                                    <span class="badge-warning">{{ event.protocol }}</span>
                                {% endif %}
                            </td>
                            <td>{{ event.level }}</td>
                            <td>{{ event.message }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Ручной ввод компонента для проверки</h2>

        <form method="post">
            <div>
                <label for="component_id">Идентификатор компонента</label>
                <input type="text" id="component_id" name="component_id">
            </div>

            <div>
                <label for="component_type">Тип компонента</label>
                <select id="component_type" name="component_type">
                    <option value="manual"></option>
                    <option value="config">config</option>
                    <option value="binary">binary</option>
                    <option value="library">library</option>
                    <option value="manual">manual</option>
                </select>
            </div>

            <div>
                <label for="content">Текущее содержимое компонента</label>
                <textarea id="content" name="content"></textarea>
            </div>

            <div>
                <label for="reference_content">Эталонное содержимое компонента</label>
                <textarea id="reference_content" name="reference_content"></textarea>
            </div>

            <button type="submit">Проверить компонент</button>
        </form>
    </div>

    <div class="section">
        <h2>Визуализация результатов проверки целостности</h2>

        <div class="charts">
            <div class="chart-box">
                <h3>Диаграмма статусов</h3>
                <canvas id="statusChart"></canvas>
            </div>

            <div class="chart-box">
                <h3>Диаграмма по типам компонентов</h3>
                <canvas id="typeChart"></canvas>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Детальный отчет проверки компонентов</h2>

        <table>
            <thead>
                <tr>
                    <th>Компонент</th>
                    <th>Тип</th>
                    <th>Текущее содержимое</th>
                    <th>Эталонное содержимое</th>
                    <th>Статус</th>
                    <th>Текущий хэш</th>
                    <th>Эталонный хэш</th>
                    <th>Время проверки</th>
                </tr>
            </thead>

            <tbody>
                {% for item in results %}
                <tr>
                    <td>{{ item.component_id }}</td>
                    <td>{{ item.component_type }}</td>
                    <td>{{ item.content }}</td>
                    <td>{{ item.reference_content }}</td>

                    <td>
                        {% if item.hash_ok %}
                            <span class="badge-ok">OK</span>
                        {% else %}
                            <span class="badge-fail">HASH_MISMATCH</span>
                        {% endif %}
                    </td>

                    <td class="hash">{{ item.current_hash }}</td>
                    <td class="hash">{{ item.reference_hash }}</td>
                    <td>{{ item.checked_at }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

</div>

<script>
    const okCount = {{ ok_count }};
    const failCount = {{ fail_count }};

    new Chart(document.getElementById('statusChart'), {
        type: 'pie',
        data: {
            labels: ['OK', 'HASH_MISMATCH'],
            datasets: [{
                data: [okCount, failCount],
                backgroundColor: ['#188038', '#d93025']
            }]
        }
    });

    const typeLabels = {{ type_labels | tojson }};
    const typeOkData = {{ type_ok_data | tojson }};
    const typeFailData = {{ type_fail_data | tojson }};

    new Chart(document.getElementById('typeChart'), {
        type: 'bar',
        data: {
            labels: typeLabels,
            datasets: [
                {
                    label: 'OK',
                    data: typeOkData,
                    backgroundColor: '#188038'
                },
                {
                    label: 'HASH_MISMATCH',
                    data: typeFailData,
                    backgroundColor: '#d93025'
                }
            ]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });

    const httpsCount = {{ https_count }};
    const httpCount = {{ http_count }};

    new Chart(document.getElementById('securityChart'), {
        type: 'doughnut',
        data: {
            labels: ['HTTPS', 'HTTP'],
            datasets: [{
                data: [httpsCount, httpCount],
                backgroundColor: ['#188038', '#fbbc04']
            }]
        }
    });
</script>

</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    global SECURITY_EVENTS

    init_db()

    if request.method == "POST":
        component_id = request.form.get("component_id", "").strip()
        component_type = request.form.get("component_type", "").strip()
        content = request.form.get("content", "").strip()
        reference_content = request.form.get("reference_content", "").strip()

        if component_id == "":
            component_id = "manual_component"

        if component_type == "":
            component_type = "manual"

        if content == "":
            content = "empty_current"

        if reference_content == "":
            reference_content = "empty_reference"

        new_component = {
            "component_id": component_id,
            "component_type": component_type,
            "content": content,
            "reference_content": reference_content,
            "checked_at": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
        }

        save_component_to_db(new_component)
        print("SAVE TO DB WORKED")

        return redirect("/")

    protocol_status, security_level, security_message = get_security_info()

    SECURITY_EVENTS.append({
        "time": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
        "protocol": protocol_status,
        "level": security_level,
        "message": security_message,
    })

    if len(SECURITY_EVENTS) > 20:
        SECURITY_EVENTS = SECURITY_EVENTS[-20:]

    db_components = load_components_from_db()
    all_components = DEMO_COMPONENTS + db_components
    results = [check_component(component) for component in all_components]

    total = len(results)
    ok_count = sum(1 for item in results if item["hash_ok"])
    fail_count = total - ok_count

    ok_percent = round(ok_count / total * 100, 1) if total else 0
    fail_percent = round(fail_count / total * 100, 1) if total else 0

    type_stats = {}

    for item in results:
        component_type = item["component_type"]

        if component_type not in type_stats:
            type_stats[component_type] = {"ok": 0, "fail": 0}

        if item["hash_ok"]:
            type_stats[component_type]["ok"] += 1
        else:
            type_stats[component_type]["fail"] += 1

    type_labels = list(type_stats.keys())
    type_ok_data = [type_stats[item]["ok"] for item in type_labels]
    type_fail_data = [type_stats[item]["fail"] for item in type_labels]

    https_count = sum(1 for event in SECURITY_EVENTS if event["protocol"] == "HTTPS")
    http_count = sum(1 for event in SECURITY_EVENTS if event["protocol"] == "HTTP")
    security_checks_total = len(SECURITY_EVENTS)

    return render_template_string(
        PAGE,
        results=results,
        total=total,
        ok_count=ok_count,
        fail_count=fail_count,
        ok_percent=ok_percent,
        fail_percent=fail_percent,
        type_labels=type_labels,
        type_ok_data=type_ok_data,
        type_fail_data=type_fail_data,
        protocol_status=protocol_status,
        security_level=security_level,
        security_message=security_message,
        https_count=https_count,
        http_count=http_count,
        security_checks_total=security_checks_total,
        security_events=list(reversed(SECURITY_EVENTS)),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)