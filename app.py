import os
import re
import secrets
from datetime import datetime
from urllib.parse import urlencode

from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_from_directory, abort
)
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# -----------------------
# Config
# -----------------------
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", secrets.token_urlsafe(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///incidents.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER", "uploads")
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH", "10485760"))  # 10MB default

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "txt", "log", "csv"}
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -----------------------
# Helpers
# -----------------------
def allowed_file(filename: str) -> bool:
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def require_role(*roles):
    def decorator(fn):
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator

def audit(action: str, incident_id=None, details: str = ""):
    entry = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        incident_id=incident_id,
        action=action,
        details=details[:500],
        ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
        user_agent=(request.headers.get("User-Agent") or "")[:255],
        created_at=datetime.utcnow()
    )
    db.session.add(entry)
    db.session.commit()

def normalize_text(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"\s+", " ", s)
    return s

# -----------------------
# Models
# -----------------------
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="Reporter")  # Admin | Analyst | Reporter
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def set_password(self, raw: str):
        self.password_hash = generate_password_hash(raw)

    def check_password(self, raw: str) -> bool:
        return check_password_hash(self.password_hash, raw)

class Incident(db.Model):
    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)

    severity = db.Column(db.String(10), nullable=False, default="Medium")  # Low/Medium/High/Critical
    status = db.Column(db.String(20), nullable=False, default="Open")      # Open/In Progress/Resolved/Closed

    category = db.Column(db.String(60), nullable=False, default="General")
    affected_asset = db.Column(db.String(200), nullable=True)
    detected_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    reporter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    assignee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    containment = db.Column(db.Text, nullable=True)
    eradication = db.Column(db.Text, nullable=True)
    recovery = db.Column(db.Text, nullable=True)
    lessons_learned = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    reporter = db.relationship("User", foreign_keys=[reporter_id])
    assignee = db.relationship("User", foreign_keys=[assignee_id])
    attachments = db.relationship("Attachment", backref="incident", cascade="all, delete-orphan")

class Attachment(db.Model):
    __tablename__ = "attachments"
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=False)

    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False, unique=True)
    content_type = db.Column(db.String(120), nullable=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("incidents.id"), nullable=True)
    action = db.Column(db.String(80), nullable=False)
    details = db.Column(db.String(500), nullable=True)
    ip_address = db.Column(db.String(80), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship("User", foreign_keys=[user_id])

# -----------------------
# Login
# -----------------------
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# -----------------------
# Bootstrap the DB and default admin
# -----------------------
@app.cli.command("initdb")
def initdb():
    db.create_all()
    # Create default admin if none exists
    admin = User.query.filter_by(role="Admin").first()
    if not admin:
        admin = User(full_name="System Admin", email="admin@example.com", role="Admin", is_active=True)
        admin.set_password("Admin@12345")
        db.session.add(admin)
        db.session.commit()
        print("Created default admin: admin@example.com / Admin@12345")
    else:
        print("DB already initialized, admin exists.")

# -----------------------
# Routes: Auth
# -----------------------
@app.get("/login")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.post("/login")
def login_post():
    email = normalize_text(request.form.get("email")).lower()
    password = request.form.get("password") or ""
    user = User.query.filter_by(email=email).first()

    if not user or not user.is_active or not user.check_password(password):
        flash("Invalid credentials or inactive account.", "danger")
        return redirect(url_for("login"))

    login_user(user)
    audit("LOGIN", details="User logged in")
    return redirect(url_for("dashboard"))

@app.post("/logout")
@login_required
def logout():
    audit("LOGOUT", details="User logged out")
    logout_user()
    return redirect(url_for("login"))

# -----------------------
# Routes: Dashboard
# -----------------------
@app.get("/")
@login_required
def dashboard():
    q = normalize_text(request.args.get("q"))
    status = normalize_text(request.args.get("status"))
    severity = normalize_text(request.args.get("severity"))
    page = int(request.args.get("page", 1))
    per_page = 10

    query = Incident.query

    # Access control:
    # Reporter sees their incidents
    # Analyst/Admin sees all
    if current_user.role == "Reporter":
        query = query.filter(Incident.reporter_id == current_user.id)

    if q:
        query = query.filter(
            db.or_(
                Incident.title.ilike(f"%{q}%"),
                Incident.description.ilike(f"%{q}%"),
                Incident.category.ilike(f"%{q}%"),
                Incident.affected_asset.ilike(f"%{q}%")
            )
        )

    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)

    query = query.order_by(Incident.updated_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    return render_template(
        "dashboard.html",
        incidents=pagination.items,
        pagination=pagination,
        q=q, status=status, severity=severity
    )

# -----------------------
# Routes: Incidents CRUD
# -----------------------
@app.get("/incidents/new")
@login_required
def incident_new():
    analysts = User.query.filter(User.role.in_(["Admin", "Analyst"]), User.is_active == True).order_by(User.full_name).all()
    return render_template("incident_new.html", analysts=analysts)

@app.post("/incidents/new")
@login_required
def incident_new_post():
    title = normalize_text(request.form.get("title"))
    description = normalize_text(request.form.get("description"))
    severity = normalize_text(request.form.get("severity")) or "Medium"
    category = normalize_text(request.form.get("category")) or "General"
    affected_asset = normalize_text(request.form.get("affected_asset"))
    assignee_id = request.form.get("assignee_id")

    if not title or not description:
        flash("Title and description are required.", "danger")
        return redirect(url_for("incident_new"))

    incident = Incident(
        title=title,
        description=description,
        severity=severity,
        category=category,
        affected_asset=affected_asset or None,
        reporter_id=current_user.id,
        assignee_id=int(assignee_id) if assignee_id else None,
        status="Open",
        detected_at=datetime.utcnow()
    )
    db.session.add(incident)
    db.session.commit()

    audit("INCIDENT_CREATE", incident_id=incident.id, details=f"Created incident: {incident.title}")
    flash(f"Incident #{incident.id} created.", "success")
    return redirect(url_for("incident_view", incident_id=incident.id))

@app.get("/incidents/<int:incident_id>")
@login_required
def incident_view(incident_id):
    incident = db.session.get(Incident, incident_id)
    if not incident:
        abort(404)

    if current_user.role == "Reporter" and incident.reporter_id != current_user.id:
        abort(403)

    return render_template("incident_view.html", incident=incident)

@app.get("/incidents/<int:incident_id>/edit")
@login_required
def incident_edit(incident_id):
    incident = db.session.get(Incident, incident_id)
    if not incident:
        abort(404)

    # Reporter can only edit their own, and only while Open
    if current_user.role == "Reporter":
        if incident.reporter_id != current_user.id:
            abort(403)
        if incident.status not in {"Open"}:
            abort(403)

    analysts = User.query.filter(User.role.in_(["Admin", "Analyst"]), User.is_active == True).order_by(User.full_name).all()
    return render_template("incident_edit.html", incident=incident, analysts=analysts)

@app.post("/incidents/<int:incident_id>/edit")
@login_required
def incident_edit_post(incident_id):
    incident = db.session.get(Incident, incident_id)
    if not incident:
        abort(404)

    if current_user.role == "Reporter":
        if incident.reporter_id != current_user.id or incident.status not in {"Open"}:
            abort(403)

    incident.title = normalize_text(request.form.get("title"))
    incident.description = normalize_text(request.form.get("description"))
    incident.severity = normalize_text(request.form.get("severity")) or incident.severity
    incident.status = normalize_text(request.form.get("status")) or incident.status
    incident.category = normalize_text(request.form.get("category")) or incident.category
    incident.affected_asset = normalize_text(request.form.get("affected_asset")) or None

    # Only Admin/Analyst can assign and fill response sections
    if current_user.role in {"Admin", "Analyst"}:
        assignee_id = request.form.get("assignee_id")
        incident.assignee_id = int(assignee_id) if assignee_id else None

        incident.containment = normalize_text(request.form.get("containment")) or None
        incident.eradication = normalize_text(request.form.get("eradication")) or None
        incident.recovery = normalize_text(request.form.get("recovery")) or None
        incident.lessons_learned = normalize_text(request.form.get("lessons_learned")) or None

    db.session.commit()
    audit("INCIDENT_UPDATE", incident_id=incident.id, details=f"Updated incident #{incident.id}")
    flash("Incident updated.", "success")
    return redirect(url_for("incident_view", incident_id=incident.id))

# -----------------------
# Routes: Attachments
# -----------------------
@app.post("/incidents/<int:incident_id>/upload")
@login_required
def incident_upload(incident_id):
    incident = db.session.get(Incident, incident_id)
    if not incident:
        abort(404)

    if current_user.role == "Reporter" and incident.reporter_id != current_user.id:
        abort(403)

    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("incident_view", incident_id=incident_id))

    if not allowed_file(file.filename):
        flash("File type not allowed.", "danger")
        return redirect(url_for("incident_view", incident_id=incident_id))

    original = secure_filename(file.filename)
    stored = f"{secrets.token_hex(16)}_{original}"
    path = os.path.join(app.config["UPLOAD_FOLDER"], stored)
    file.save(path)

    att = Attachment(
        incident_id=incident_id,
        original_name=original,
        stored_name=stored,
        content_type=file.content_type,
        uploaded_by=current_user.id
    )
    db.session.add(att)
    db.session.commit()

    audit("ATTACHMENT_UPLOAD", incident_id=incident_id, details=f"Uploaded {original}")
    flash("File uploaded.", "success")
    return redirect(url_for("incident_view", incident_id=incident_id))

@app.get("/attachments/<int:attachment_id>/download")
@login_required
def attachment_download(attachment_id):
    att = db.session.get(Attachment, attachment_id)
    if not att:
        abort(404)

    incident = db.session.get(Incident, att.incident_id)
    if not incident:
        abort(404)

    if current_user.role == "Reporter" and incident.reporter_id != current_user.id:
        abort(403)

    audit("ATTACHMENT_DOWNLOAD", incident_id=incident.id, details=f"Downloaded {att.original_name}")
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        att.stored_name,
        as_attachment=True,
        download_name=att.original_name
    )

# -----------------------
# Routes: User management (Admin only)
# -----------------------
@app.get("/admin/users")
@login_required
@require_role("Admin")
def users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("users.html", users=users)

@app.get("/admin/users/new")
@login_required
@require_role("Admin")
def user_new():
    return render_template("user_new.html")

@app.post("/admin/users/new")
@login_required
@require_role("Admin")
def user_new_post():
    full_name = normalize_text(request.form.get("full_name"))
    email = normalize_text(request.form.get("email")).lower()
    role = normalize_text(request.form.get("role")) or "Reporter"
    password = request.form.get("password") or ""

    if not full_name or not email or not password:
        flash("Full name, email, and password are required.", "danger")
        return redirect(url_for("user_new"))

    if role not in {"Admin", "Analyst", "Reporter"}:
        flash("Invalid role.", "danger")
        return redirect(url_for("user_new"))

    if User.query.filter_by(email=email).first():
        flash("Email already exists.", "danger")
        return redirect(url_for("user_new"))

    u = User(full_name=full_name, email=email, role=role, is_active=True)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()

    audit("USER_CREATE", details=f"Created user {email} ({role})")
    flash("User created.", "success")
    return redirect(url_for("users"))

@app.post("/admin/users/<int:user_id>/toggle")
@login_required
@require_role("Admin")
def user_toggle(user_id):
    u = db.session.get(User, user_id)
    if not u:
        abort(404)
    if u.id == current_user.id:
        flash("You cannot deactivate your own account.", "danger")
        return redirect(url_for("users"))

    u.is_active = not u.is_active
    db.session.commit()

    audit("USER_TOGGLE", details=f"Toggled user {u.email} active={u.is_active}")
    flash("User updated.", "success")
    return redirect(url_for("users"))

# -----------------------
# Routes: Audit log (Admin only)
# -----------------------
@app.get("/admin/audit")
@login_required
@require_role("Admin")
def audit_log():
    page = int(request.args.get("page", 1))
    per_page = 20
    query = AuditLog.query.order_by(AuditLog.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template("audit.html", logs=pagination.items, pagination=pagination)

# -----------------------
# Error handlers
# -----------------------
@app.errorhandler(403)
def forbidden(_):
    return render_template("base.html", content_title="403 Forbidden", content_body="You do not have permission to access this page."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("base.html", content_title="404 Not Found", content_body="The resource does not exist."), 404

# -----------------------
# Main
# -----------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
