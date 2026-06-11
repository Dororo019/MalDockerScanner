from flask import Flask, render_template, request
import subprocess
import os

#Import the Scanners
from static_scan.trivy_scan import scan_with_trivy
from static_scan.yara_scan import scan_with_yara
from static_scan.clamav_scan import scan_with_clamav
from dynamic_scan.falco_monitor import check_falco_alerts
from ml_model.risk_aggregator import calculate_risk_score

app = Flask(__name__, template_folder='templates', static_folder='static')

def ensure_image_exists(image_name):
    """
    First, it will check if an image exists locally. If not, it automatically pulls it from Docker Hub.
    """
    try:
        # 1. For checking if an image exists locally using 'docker inspect'
        subprocess.run(
            ['docker', 'image', 'inspect', image_name], 
            check=True, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        return True 
    except subprocess.CalledProcessError:
        # 2. If an image is not found, try PULL it again
        print(f"[*] Image '{image_name}' not found locally. Auto-pulling from Docker Hub...")
        try:
            subprocess.run(['docker', 'pull', image_name], check=True)
            print(f"[*] Successfully pulled {image_name}")
            return True
        except subprocess.CalledProcessError:
            print(f"[!] Failed to pull {image_name}. It might not exist or is private.")
            return False

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    error = None
    
    if request.method == 'POST':
        image_name = request.form.get('image_name', '').strip()
        
        if not image_name:
            error = 'Please enter a Docker image name (e.g., alpine:latest)'
            return render_template('index.html', error=error)
        
        if ' ' in image_name:
            image_name = image_name.replace(' ', ':')
        
        try:
            print(f"\n{'='*60}")
            print(f"🔍 STARTING SCAN FOR: {image_name}")
            print(f"{'='*60}\n")
            
            #Counter-checking for image: AUTO-PULL CHECK 
            if not ensure_image_exists(image_name):
                error = f"Could not find or pull image '{image_name}'. Check spelling or internet connection."
                return render_template('index.html', error=error)
            
            #STEP 1: Trivy Scan 
            print("[1/4] Running Trivy vulnerability scan...")
            trivy_result = scan_with_trivy(image_name)
            
            #STEP 2: YARA Scan
            print("[2/4] Running YARA malware detection...")
            yara_result = scan_with_yara(image_name)
            
            # STEP 3: ClamAV Scan
            print("[3/4] Running ClamAV antivirus scan...")
            clamav_result = scan_with_clamav(image_name)
            
            #STEP 4: Falco Scan
            print("[4/4] Checking Falco runtime alerts...")
            falco_result = check_falco_alerts()
            
            #STEP 5: Risk Calculation tab
            print("\n[*] Aggregating results and calculating risk...")
            risk_assessment = calculate_risk_score(
                trivy_result,
                yara_result,
                clamav_result,
                falco_result
            )
            
            results = {
                'image_name': image_name,
                'trivy': trivy_result,
                'yara': yara_result,
                'clamav': clamav_result,
                'falco': falco_result,
                'risk': risk_assessment
            }
            
            print(f"✅ SCAN COMPLETE - Final Risk Level: {risk_assessment['risk_level']}")
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"❌ [CRITICAL ERROR] {str(e)}")
            error = f"System Error: {str(e)}"

    return render_template('index.html', results=results, error=error)

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
