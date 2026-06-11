from app.app import app

if __name__ == '__main__':
    print("\n" + "="*50)
    print("🔒 Malicious Docker Images Scanner")
    print("="*50)
    print("\nStarting Flask server...")
    print("Open browser to: http://localhost:5000\n")
    app.run(debug=True, host='127.0.0.1', port=5000)
