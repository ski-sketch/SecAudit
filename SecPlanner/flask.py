from flask import Flask, jsonify
from subprocess import run

app = Flask(__name__)

@app.route('/start-scan', methods=['POST'])
def start_scan():
    try:
        # Run Vuln.Scan.py script
        result = run(['python3', 'Vuln.Scan.py'], capture_output=True, text=True)
        return jsonify({"message": "Scan started", "output": result.stdout})
    except Exception as e:
        return jsonify({"error": f"Error starting scan: {str(e)}"}), 500

@app.route('/start-monitor', methods=['POST'])
def start_monitor():
    try:
        # Run Sec.Monitor.py script
        result = run(['python3', 'Sec.Monitor.py'], capture_output=True, text=True)
        return jsonify({"message": "Monitor started", "output": result.stdout})
    except Exception as e:
        return jsonify({"error": f"Error starting monitor: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)