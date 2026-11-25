import os, uuid, time
from datetime import datetime
from flask import Flask, render_template, request, send_from_directory, redirect, url_for
import qrcode
from werkzeug.utils import secure_filename

try:
    from utils.ocr import extract_text
    from utils.detection import detect_sensitive
    from utils.masking import mask_aadhaar, mask_pan
    from utils.image_masking import mask_aadhaar_in_image
    from utils.face_verify import verify_faces
    from utils.watermark import add_watermark
except ImportError:
    pass

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
VAULT_FOLDER = os.path.join(BASE_DIR, "vault", "default_user")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(VAULT_FOLDER, exist_ok=True)

shared_links = {}
EXPIRY_TIME = 180 # 3 MINUTE STRICT EXPIRY RULE

# ⚠️ Notification Module (Email Simulation)
def send_email_notification(event_type, recipient, info):
    print(f"\n=====================================")
    print(f"[SMTP EMAIL ALERT FIRED]")
    print(f"EVENT: {event_type}")
    print(f"TARGET: {recipient}")
    print(f"DATA: {info}")
    print(f"=====================================\n")


@app.route("/")
def landing():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/upload/<purpose>", methods=["GET", "POST"])
def upload_page(purpose):
    if request.method == "POST":
        files = request.files.getlist("file")
        if not files or files[0].filename == '':
            return "No file uploaded", 400

        selfie = request.files.get("selfie")
        recipient_name = request.form.get("recipient_name", "General").strip() or "General"
        one_time_view = request.form.get("one_time_view") == "on"
        
        processed_files = []
        face_match = None
        
        # 🛡️ Smart Protection Security Score Algorithm
        score = 0
        if purpose in ['hotel', 'sharing', 'qr']: score += 30      # OCR Masking Layer
        if purpose != 'vault': score += 20                         # Core Watermarking
        if purpose != 'vault': score += 20                         # Expiry Constraints
        if one_time_view: score += 30                              # Advanced Burn Access
        
        for file in files:
            fname = secure_filename(file.filename)
            unique_fname = str(uuid.uuid4()) + "_" + fname
            
            if purpose == 'vault':
                path = os.path.join(VAULT_FOLDER, unique_fname)
                file.save(path)
                continue 
                
            path = os.path.join(UPLOAD_FOLDER, unique_fname)
            file.save(path)
            
            text = extract_text(path)
            detected = detect_sensitive(text) if text else {}
            masked_text = text
            current_img_path = path

            # Core Security Module: MASKING
            if purpose in ['hotel', 'sharing', 'qr'] and text:
                for num in detected.get("aadhaar", []):
                    masked_text = masked_text.replace(num, mask_aadhaar(num))
                for pan in detected.get("pan", []):
                    masked_text = masked_text.replace(pan, mask_pan(pan))
                current_img_path = mask_aadhaar_in_image(path)
            
            # Core Security Module: WATERMARKS
            if purpose == 'verification':
                watermark_text = "Verified Identity"
            else:
                formatted_purpose = purpose.replace('_', ' ').title()
                watermark_text = f"Shared with: {recipient_name} | Mode: {formatted_purpose}"

            final_img = add_watermark(current_img_path, text=watermark_text)
            
            processed_files.append({
                "original": text,
                "masked": masked_text,
                "filename": os.path.basename(final_img)
            })
            
            # Biometric Module
            if purpose == 'verification' and selfie and face_match is None:
                sname = str(uuid.uuid4()) + "_" + secure_filename(selfie.filename)
                spath = os.path.join(UPLOAD_FOLDER, sname)
                selfie.save(spath)
                face_match = verify_faces(path, spath)

        if purpose == 'vault':
            return redirect(url_for('my_vault'))

        # Construct Access Control Tracking Payload
        link_id = str(uuid.uuid4())
        shared_links[link_id] = {
            "files": [f["filename"] for f in processed_files],
            "purpose": purpose,
            "recipient_name": recipient_name,
            "time": time.time(),
            "views": 0,
            "last_access": None,
            "one_time": one_time_view,
            "accessed": False,
            "expired": False,
            "security_score": score,
            "suspicious_activity": False
        }

        share_link = f"/view/{link_id}"
        full_share_url = request.host_url.rstrip('/') + share_link
        
        qr = qrcode.make(full_share_url)
        qr_filename = f"qr_{link_id}.png"
        qr.save(os.path.join(UPLOAD_FOLDER, qr_filename))

        return render_template(
            "result.html",
            purpose=purpose,
            recipient_name=recipient_name,
            processed_files=processed_files,
            face_match=face_match,
            share_link=full_share_url,
            qr_image=qr_filename,
            score=score,
            link_id=link_id
        )

    return render_template("upload.html", purpose=purpose)

@app.route('/revoke/<link_id>', methods=['POST'])
def revoke_link(link_id):
    from flask import jsonify
    data = shared_links.get(link_id)
    if data:
        data["expired"] = True
        send_email_notification("Manual Revocation", data["recipient_name"], "Sender manually terminated the link prematurely.")
        
        # Hard File System Purge
        if data.get("files"):
            for f in data["files"]:
                fp = os.path.join(UPLOAD_FOLDER, f)
                if os.path.exists(fp): 
                    try: os.remove(fp) 
                    except: pass
            data["files"] = []
        return jsonify({"success": True})
    return jsonify({"success": False})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route('/vault_files/<filename>')
def vault_file(filename):
    return send_from_directory(VAULT_FOLDER, filename, as_attachment=True)

@app.route('/my-vault')
def my_vault():
    files_data = []
    if os.path.exists(VAULT_FOLDER):
        for f in os.listdir(VAULT_FOLDER):
            fpath = os.path.join(VAULT_FOLDER, f)
            if os.path.isfile(fpath):
                stat = os.stat(fpath)
                upload_date = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                files_data.append({
                    "name": f,
                    "date": upload_date,
                    "size": round(stat.st_size / 1024, 2)
                })
    files_data.sort(key=lambda x: x['date'], reverse=True)
    return render_template("vault.html", vault_files=files_data)

@app.route('/view/<link_id>')
def view_file(link_id):
    data = shared_links.get(link_id)

    if not data:
        return render_template("view_dashboard.html", error="Link invalid or completely removed from server.")

    purpose = data.get("purpose", "document")
    elapsed = time.time() - data["time"]

    # Access Control Module -> AUTO DELETE LOGIC
    if elapsed > EXPIRY_TIME or data.get("expired"):
        data["expired"] = True
        data["suspicious_activity"] = True
        
        # Fire Notification
        send_email_notification("Link Expired Alert", data["recipient_name"], f"Attempted view after {elapsed}s.")
        
        # Hard File System Purge
        if data.get("files"):
            for f in data["files"]:
                fp = os.path.join(UPLOAD_FOLDER, f)
                if os.path.exists(fp): 
                    try: os.remove(fp) 
                    except: pass
            data["files"] = []

        return render_template("view_dashboard.html", error="Link expired. Time limit exceeded, payload destroyed.")

    # Access Control Module -> BURN AFTER READING VIEW LOGIC
    if data["one_time"] and data["accessed"]:
        data["suspicious_activity"] = True
        send_email_notification("Security Violation", data["recipient_name"], "Burn After Reading link was accessed multiple times.")
        return render_template("view_dashboard.html", error="🔒 This link was already used once")

    # Smart Protection Module -> RAPID ACCESS DETECTION
    current_time = time.time()
    if data["last_access"] and (current_time - data["last_access"] < 2.5):
        data["suspicious_activity"] = True

    # Valid State -> Register Handshake
    data["views"] += 1
    data["last_access"] = current_time
    data["accessed"] = True
    
    # Smart Protection Module -> EXCESSIVE VIEWS
    if data["views"] > 3:
        data["suspicious_activity"] = True

    send_email_notification("Document Accessed", data["recipient_name"], f"View Count Reached: {data['views']}")

    files_to_show = data.get("files", [])
    formatted_access = datetime.fromtimestamp(data["last_access"]).strftime('%H:%M:%S | %Y-%m-%d')
    upload_time = datetime.fromtimestamp(data["time"]).strftime('%H:%M:%S | %Y-%m-%d')

    return render_template(
        "view_dashboard.html",
        files=files_to_show,
        purpose=purpose,
        recipient_name=data.get("recipient_name", "General"),
        upload_time=upload_time,
        last_access=formatted_access,
        views=data["views"],
        time_left=int(EXPIRY_TIME - elapsed),
        score=data["security_score"],
        suspicious=data["suspicious_activity"],
        one_time=data["one_time"],
        error=None
    )

if __name__ == "__main__":
    app.run(debug=True)