from flask import Flask, request, render_template, jsonify
import pandas as pd
import numpy as np
import string
import joblib

sql_keywords = pd.read_csv('static/SQLKeywords.txt', index_col=False)
js_keywords = pd.read_csv("static/JavascriptKeywords.txt", index_col=False)

# Load the pre-trained model
xgb_classifier = joblib.load('model/xgb_classifier.pkl')

# Initialize Flask app
app = Flask(__name__)

# Function to calculate features and predict
def calculate_features_and_predict(payload):
    features = {}
    payload = str(payload)
    features['length'] = len(payload)
    features['non-printable'] = len([1 for letter in payload if letter not in string.printable])
    features['punctuation'] = len([1 for letter in payload if letter in string.punctuation])
    features['min-byte'] = min(bytearray(payload, 'utf-8'))
    features['max-byte'] = max(bytearray(payload, 'utf-8'))
    features['mean-byte'] = np.mean(bytearray(payload, 'utf-8'))
    features['std-byte'] = np.std(bytearray(payload, 'utf-8'))
    features['distinct-byte'] = len(set(bytearray(payload, 'utf-8')))
    features['sql-keywords'] = len([1 for keyword in sql_keywords['Keyword'] if str(keyword).lower() in payload.lower()])
    features['js-keywords'] = len([1 for keyword in js_keywords['Keyword'] if str(keyword).lower() in payload.lower()])
    payload_df = pd.DataFrame(features, index=[0])
    result = xgb_classifier.predict(payload_df)
    return result[0]

# Define routes
@app.route('/')
def home():
    return render_template('index.html', title="Home")

@app.route('/xss')
def xss():
    return render_template('xss.html', title="XSS Protection")

@app.route('/sqli')
def sqli():
    return render_template('sqli.html', title="SQL Injection Protection")

@app.route('/html-injection')
def html_injection():
    return render_template('html_injection.html', title="HTML Injection Protection")

@app.route('/iframe-injection')
def iframe_injection():
    return render_template('iframe_injection.html', title="Iframe Injection Protection")

@app.route('/command-injection')
def command_injection():
    return render_template('command_injection.html', title="Command Injection Protection")

@app.route('/path-traversal')
def path_traversal():
    return render_template('path_traversal.html', title="Path Traversal Protection")

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    payload = data.get('payload', '')
    result = calculate_features_and_predict(payload)
    if result > 0:
        return jsonify({"status": "malicious", "message": "Attack detected by Firewall - 403 Forbidden"})
    else:
        return jsonify({"status": "safe", "message": "Your payload is safe - 200 OK"})

if __name__ == '__main__':
    app.run(debug=True)
