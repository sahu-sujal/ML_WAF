from flask import Flask, request, render_template, jsonify
import pandas as pd
import numpy as np
import string
from tensorflow.keras.models import load_model
import pickle


# Loading keyword files
try:
    sql_keywords = pd.read_csv('static/SQLKeywords.txt', index_col=False)
    js_keywords = pd.read_csv('static/JavascriptKeywords.txt', index_col=False)
except FileNotFoundError as e:
    print(f"Error: {e}. Please ensure SQLKeywords.txt and JavascriptKeywords.txt are in static/")
    raise

# Load the pre-trained deep learning model and scaler
model = load_model('model/firewall_model.h5')
with open('model/scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

# Define numerical columns in the same order as during training
numerical_columns = [
    'length', 'non-printable', 'punctuation', 'min-byte', 'max-byte',
    'mean-byte', 'std-byte', 'distinct-byte', 'sql-keywords', 'js-keywords'
]

# Initialize Flask app
app = Flask(__name__)

# Function to calculate features and predict
def calculate_features_and_predict(payload):
    features = {}
    payload = str(payload)
    features['length'] = len(payload)
    features['non-printable'] = len([1 for letter in payload if letter not in string.printable])
    features['punctuation'] = len([1 for letter in payload if letter in string.punctuation])
    try:
        byte_array = bytearray(payload, 'utf-8')
        features['min-byte'] = min(byte_array) if byte_array else 0
        features['max-byte'] = max(byte_array) if byte_array else 0
        features['mean-byte'] = np.mean(byte_array) if byte_array else 0
        features['std-byte'] = np.std(byte_array) if byte_array else 0
        features['distinct-byte'] = len(set(byte_array))
    except UnicodeEncodeError:
        features['min-byte'] = 0
        features['max-byte'] = 0
        features['mean-byte'] = 0
        features['std-byte'] = 0
        features['distinct-byte'] = 0
    features['sql-keywords'] = len([1 for keyword in sql_keywords['Keyword'] if str(keyword).lower() in payload.lower()])
    features['js-keywords'] = len([1 for keyword in js_keywords['Keyword'] if str(keyword).lower() in payload.lower()])
    
    # Creating DataFrame with features in correct order
    payload_df = pd.DataFrame(features, index=[0])[numerical_columns]
    
    # Scaling the features
    payload_scaled = scaler.transform(payload_df)
    
    # Predicting with the deep learning model
    proba = model.predict(payload_scaled, verbose=0)[0][0]
    result = 1 if proba > 0.5 else 0
    return result

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