from flask import Flask, render_template, request
from scanner import scan_target  # Import your function!

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target')
    
    # 1. Input Validation 
    if not target:
        return "Error: No target specified", 400
    
    # 2. Run the Scan 
    try:
        scan_results = scan_target(target)
    except Exception as e:
        return f"Error occurred: {e}", 500
        
    # 3. Render the Report
    return render_template('report.html', target=target, results=scan_results)

if __name__ == '__main__':
    app.run(debug=True)