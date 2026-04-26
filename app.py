from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# ─── IMPORT MODULES ───
try:
    from modules import port_scanner
    print('[OK] port_scanner loaded')
except Exception as e:
    print('[ERROR] port_scanner: ' + str(e))

try:
    from modules import log_analyzer
    print('[OK] log_analyzer loaded')
except Exception as e:
    print('[ERROR] log_analyzer: ' + str(e))

try:
    from modules import hash_tools
    print('[OK] hash_tools loaded')
except Exception as e:
    print('[ERROR] hash_tools: ' + str(e))

try:
    from modules import payload_lab
    print('[OK] payload_lab loaded')
except Exception as e:
    print('[ERROR] payload_lab: ' + str(e))

try:
    from modules import network_monitor
    print('[OK] network_monitor loaded')
except Exception as e:
    print('[ERROR] network_monitor: ' + str(e))

try:
    from modules import report_generator
    print('[OK] report_generator loaded')
except Exception as e:
    print('[ERROR] report_generator: ' + str(e))

# ─── PAGES ───
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/scanner')
def scanner():
    return render_template('scanner.html')

@app.route('/logs')
def logs():
    return render_template('logs.html')

@app.route('/network')
def network():
    return render_template('network.html')

@app.route('/payload')
def payload():
    return render_template('payload.html')

@app.route('/hash')
def hash_page():
    return render_template('hash.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

# ─── API: PORT SCANNER ───
@app.route('/api/scan', methods=['POST'])
def api_scan():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data received'}), 400
        target    = data.get('target', '')
        scan_type = data.get('scan_type', 'common')
        if not target:
            return jsonify({'error': 'No target provided'}), 400
        result = port_scanner.scan(target, scan_type)
        return jsonify(result)
    except Exception as e:
        print('[ERROR] api_scan: ' + str(e))
        return jsonify({'error': str(e)}), 500

# ─── API: LOG ANALYSIS ───
@app.route('/api/analyze_logs', methods=['POST'])
def api_analyze_logs():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data received'}), 400
        logs_text = data.get('logs', '')
        if not logs_text:
            return jsonify({'error': 'No logs provided'}), 400
        result = log_analyzer.analyze(logs_text)
        return jsonify(result)
    except Exception as e:
        print('[ERROR] api_analyze_logs: ' + str(e))
        return jsonify({'error': str(e)}), 500

# ─── API: HASH ───
@app.route('/api/hash', methods=['POST'])
def api_hash():
    try:
        data = request.json
        if not data:
            return jsonify({'error': 'No data received'}), 400
        text   = data.get('text', '')
        result = hash_tools.generate_all(text)
        return jsonify(result)
    except Exception as e:
        print('[ERROR] api_hash: ' + str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify_hash', methods=['POST'])
def api_verify_hash():
    try:
        data     = request.json
        text     = data.get('text', '')
        hash_val = data.get('hash', '')
        result   = hash_tools.verify(text, hash_val)
        return jsonify(result)
    except Exception as e:
        print('[ERROR] api_verify_hash: ' + str(e))
        return jsonify({'error': str(e)}), 500

# ─── API: PAYLOAD LAB ───
@app.route('/api/payloads', methods=['GET'])
def api_payloads():
    try:
        category = request.args.get('category', 'sql')
        result   = payload_lab.get_payloads(category)
        return jsonify(result)
    except Exception as e:
        print('[ERROR] api_payloads: ' + str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/api/encode', methods=['POST'])
def api_encode():
    try:
        data   = request.json
        text   = data.get('text', '')
        method = data.get('method', 'url')
        result = payload_lab.encode(text, method)
        return jsonify(result)
    except Exception as e:
        print('[ERROR] api_encode: ' + str(e))
        return jsonify({'error': str(e)}), 500

# ─── API: NETWORK MONITOR ───
@app.route('/api/network/start', methods=['POST'])
def api_net_start():
    try:
        result = network_monitor.start_capture()
        return jsonify(result)
    except Exception as e:
        print('[ERROR] api_net_start: ' + str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/api/network/stop', methods=['POST'])
def api_net_stop():
    try:
        result = network_monitor.stop_capture()
        return jsonify(result)
    except Exception as e:
        print('[ERROR] api_net_stop: ' + str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/api/network/packets', methods=['GET'])
def api_net_packets():
    try:
        result = network_monitor.get_packets()
        return jsonify(result)
    except Exception as e:
        print('[ERROR] api_net_packets: ' + str(e))
        return jsonify({'error': str(e)}), 500

# ─── API: REPORTS ───
@app.route('/api/reports/generate', methods=['POST'])
def api_generate_report():
    try:
        data   = request.json
        result = report_generator.generate(data)
        return jsonify(result)
    except Exception as e:
        print('[ERROR] api_generate_report: ' + str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/list', methods=['GET'])
def api_list_reports():
    try:
        result = report_generator.list_reports()
        return jsonify(result)
    except Exception as e:
        print('[ERROR] api_list_reports: ' + str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/download/<filename>', methods=['GET'])
def api_download_report(filename):
    try:
        path = report_generator.get_report_path(filename)
        return send_file(path, as_attachment=True)
    except Exception as e:
        print('[ERROR] api_download_report: ' + str(e))
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)