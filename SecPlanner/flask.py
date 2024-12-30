from flask import Flask, jsonify
from subprocess import run

app = Flask(__name__)

@app.route('/start-scan', methods=['POST'])
def start_scan():
    try:
        # Run Vuln.Scan.py script
        result = run(['python3', 'Vuln.Scan.py'], capture_output=True, text=True)
        return jsonify({"message": "Scan started", "output": result.stdout}), 200
    except Exception as e:
        return jsonify({"message": "Error starting scan", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
