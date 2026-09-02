import csv
import io
import os
import re
import db_compat
from datetime import date, datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, g, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-this")
DB_PATH = "database.db"
PROFILE_PHOTO_DIR = os.path.join("static", "uploads", "profile_photos")
ALLOWED_PHOTO_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

# Only Gmail addresses are accepted on the public self-signup form.
GMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+-]+@gmail\.com$", re.IGNORECASE)

# Name fields: letters only, no digits or symbols. First/last name is a single
# word (no spaces); a combined "full name" field allows spaces between words.
NAME_RE = re.compile(r"^[A-Za-z]+$")
FULL_NAME_RE = re.compile(r"^[A-Za-z]+(?: [A-Za-z]+)*$")

# ---------------------------------------------------------------------------
# Fixed reference data (seeded into the departments/designations tables the
# first time the app runs; from then on those tables are the source of truth
# and can be managed from the UI).
# ---------------------------------------------------------------------------
DEPARTMENTS = [
    "Engineering",
    "Human Resources",
    "Sales",
    "Marketing",
    "Finance",
    "Operations",
    "Customer Support",
]

DESIGNATIONS = [
    "Frontend Developer",
    "Backend Developer",
    "Full Stack Developer",
    "QA Engineer",
    "Product Manager",
    "HR Executive",
    "HR Manager",
    "Sales Associate",
    "Sales Manager",
    "Marketing Specialist",
    "Financial Analyst",
    "Operations Manager",
    "Support Specialist",
]

# Which department each of the fixed designations above belongs to. Used to seed
# designations.department on first run / migration so the designation dropdown on
# signup and Add Employee can be filtered to the selected department instead of
# showing every designation for every department.
DESIGNATION_DEPARTMENT_MAP = {
    "Frontend Developer": "Engineering",
    "Backend Developer": "Engineering",
    "Full Stack Developer": "Engineering",
    "QA Engineer": "Engineering",
    "Product Manager": "Engineering",
    "HR Executive": "Human Resources",
    "HR Manager": "Human Resources",
    "Sales Associate": "Sales",
    "Sales Manager": "Sales",
    "Marketing Specialist": "Marketing",
    "Financial Analyst": "Finance",
    "Operations Manager": "Operations",
    "Support Specialist": "Customer Support",
}

ATTENDANCE_STATUSES = ["Present", "Absent", "On Leave", "Half Day"]


def sync_employee_status_from_attendance(db, emp_id, attendance_status, attendance_date):
    """Keep employees.status (used across the dashboard) in step with today's attendance.
    Only applies to today's date so editing a past date doesn't change someone's current status,
    and never overrides an employee who has already been marked Resigned."""
    if attendance_date != date.today().isoformat():
        return
    row = db.execute("SELECT status FROM employees WHERE id = ?", (emp_id,)).fetchone()
    if not row or row["status"] == "Resigned":
        return
    new_status = "On Leave" if attendance_status == "On Leave" else "Active"
    if row["status"] != new_status:
        db.execute("UPDATE employees SET status = ? WHERE id = ?", (new_status, emp_id))
LEAVE_TYPES = ["Sick Leave", "Casual Leave", "Earned Leave", "Unpaid Leave","Maternity Leave", "Paternity Leave", "Bereavement Leave", "Compensatory Off", "Study Leave", "Sabbatical Leave", "Other"]
LEAVE_STATUSES = ["Pending", "Approved", "Rejected"]


def mark_attendance_for_leave(db, employee_id, start_date, end_date):
    """Fill in an attendance row for every day an approved leave covers, so the
    days show up on the attendance sheet instead of looking unaccounted-for."""
    start = datetime.strptime(start_date, "%Y-%m-%d").date()
    end = datetime.strptime(end_date, "%Y-%m-%d").date()
    day = start
    while day <= end:
        iso = day.isoformat()
        existing = db.execute(
            "SELECT id FROM attendance WHERE employee_id = ? AND date = ?", (employee_id, iso)
        ).fetchone()
        if existing:
            db.execute(
                "UPDATE attendance SET status = 'On Leave', check_in = NULL, check_out = NULL WHERE id = ?",
                (existing["id"],),
            )
        else:
            db.execute(
                "INSERT INTO attendance (employee_id, date, status) VALUES (?, ?, 'On Leave')",
                (employee_id, iso),
            )
        day += timedelta(days=1)

# Role-based access control: three roles.
#   Admin      - full access to every module, including audit logs.
#   HR Manager - manage employees, departments, designations, attendance,
#                approve/reject leave, view reports. No audit log access.
#   Employee   - view own profile, mark/view own attendance, apply for and
#                track their own leave.
ROLES = ["Admin", "HR Manager", "Employee"]


# ---------------------------------------------------------------------------
# Auth / access-control helpers
# ---------------------------------------------------------------------------
def login_required(view):
    """Redirect to /login if the user hasn't signed in yet."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*allowed_roles):
    """Restrict a view to the given roles. Must be stacked under @login_required."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("logged_in"):
                return redirect(url_for("login"))
            if session.get("role") not in allowed_roles:
                flash("You don't have permission to access that page.")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


def current_employee_id():
    return session.get("employee_id")


def create_login_for_employee(db, employee_id, name):
    """Create a default login account for a newly added employee.
    Username = employee's name, password = '123'. If that username is
    already taken, a numeric suffix is added to keep it unique."""
    base_username = name.strip()
    username = base_username
    suffix = 2
    while db.execute(
        "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,)
    ).fetchone():
        username = f"{base_username} {suffix}"
        suffix += 1

    emp = db.execute("SELECT email FROM employees WHERE id = ?", (employee_id,)).fetchone()
    email = emp["email"] if emp else None

    db.execute(
        "INSERT INTO users (username, password_hash, full_name, role, employee_id, email) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (username, generate_password_hash("123"), name, "Employee", employee_id, email),
    )
    return username


def ensure_unique_username(db, base_username):
    """Return base_username as-is if free, otherwise add a numeric suffix
    until it finds one that's free (used when approving a signup request,
    in case the requested username got taken while it was pending)."""
    base_username = base_username.strip()
    username = base_username
    suffix = 2
    while db.execute(
        "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,)
    ).fetchone():
        username = f"{base_username}{suffix}"
        suffix += 1
    return username


def log_audit(action, details=""):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (timestamp, username, role, action, details) VALUES (?, ?, ?, ?, ?)",
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            session.get("username", "system"),
            session.get("role", ""),
            action,
            details,
        ),
    )
    db.commit()


@app.context_processor
def inject_user():
    announcement_count = 0
    pending_signup_count = 0
    pending_leave_count = 0
    if session.get("logged_in"):
        try:
            db = get_db()
            user_id = session.get("user_id")
            if user_id:
                # Only announcements this user hasn't opened the list for yet.
                announcement_count = db.execute(
                    "SELECT COUNT(*) FROM announcements a WHERE NOT EXISTS "
                    "(SELECT 1 FROM announcement_reads r WHERE r.announcement_id = a.id AND r.user_id = ?)",
                    (user_id,),
                ).fetchone()[0]
            else:
                announcement_count = db.execute("SELECT COUNT(*) FROM announcements").fetchone()[0]
        except db_compat.OperationalError:
            announcement_count = 0

        if session.get("role") == "Admin":
            try:
                pending_signup_count = db.execute(
                    "SELECT COUNT(*) FROM signup_requests WHERE status = 'Pending'"
                ).fetchone()[0]
            except db_compat.OperationalError:
                pending_signup_count = 0

        if session.get("role") in ("Admin", "HR Manager"):
            try:
                pending_leave_count = db.execute(
                    "SELECT COUNT(*) FROM leaves WHERE status = 'Pending'"
                ).fetchone()[0]
            except db_compat.OperationalError:
                pending_leave_count = 0

    return {
        "current_role": session.get("role"),
        "current_username": session.get("username"),
        "current_full_name": session.get("full_name"),
        "current_photo": session.get("photo_path"),
        "announcement_count": announcement_count,
        "pending_signup_count": pending_signup_count,
        "pending_leave_count": pending_leave_count,
    }


# ---------------------------------------------------------------------------
# Avatar helpers (initials-based avatars used across employee views)
# ---------------------------------------------------------------------------
AVATAR_PALETTE = [
    "#2f6690", "#4c9a78", "#c97b3b", "#b85c5c",
    "#7c5cb8", "#3d8f8f", "#a3762f", "#5c6bb8",
]


def initials_for(name):
    name = (name or "").strip()
    if not name:
        return "?"
    parts = name.split()
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()


def color_for(name):
    name = (name or "").strip()
    index = sum(ord(ch) for ch in name) % len(AVATAR_PALETTE) if name else 0
    return AVATAR_PALETTE[index]


app.jinja_env.globals["initials_for"] = initials_for
app.jinja_env.globals["color_for"] = color_for


# ---------------------------------------------------------------------------
# Relative time helper ("6 min ago", "3 hours ago", "5 days ago", ...)
# ---------------------------------------------------------------------------
def timeago(value):
    if not value:
        return ""
    if isinstance(value, datetime):
        dt = value
    else:
        dt = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(str(value), fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return str(value)

    seconds = int((datetime.now() - dt).total_seconds())
    if seconds < 0:
        seconds = 0

    if seconds < 60:
        return "Just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min ago" if minutes == 1 else f"{minutes} mins ago"
    hours = minutes // 60
    if hours < 24:
        return "1 hour ago" if hours == 1 else f"{hours} hours ago"
    days = hours // 24
    if days < 7:
        return "1 day ago" if days == 1 else f"{days} days ago"
    weeks = days // 7
    if days < 30:
        return "1 week ago" if weeks == 1 else f"{weeks} weeks ago"
    months = days // 30
    if days < 365:
        return "1 month ago" if months == 1 else f"{months} months ago"
    years = days // 365
    return "1 year ago" if years == 1 else f"{years} years ago"


app.jinja_env.filters["timeago"] = timeago


# ---------------------------------------------------------------------------
# Database setup
# ---------------------------------------------------------------------------
def get_db():
    """Open a DB connection for this request (reused if already open).
    Talks to Postgres when DATABASE_URL is set (e.g. on Render), otherwise
    falls back to the local SQLite file for offline development."""
    if "db" not in g:
        g.db = db_compat.connect(DB_PATH)
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the tables (if they don't exist yet) and seed sample/default rows."""
    db = db_compat.connect(DB_PATH)
    with open(db_compat.SCHEMA_FILE) as f:
        db.executescript(f.read())

    # Lightweight migration in case an older database.db (without phone/salary) is reused.
    existing_cols = {row["name"] for row in db.execute("PRAGMA table_info(employees)")}
    if "phone" not in existing_cols:
        db.execute("ALTER TABLE employees ADD COLUMN phone TEXT")
    if "salary" not in existing_cols:
        db.execute("ALTER TABLE employees ADD COLUMN salary REAL")
    if "registration_no" not in existing_cols:
        db.execute("ALTER TABLE employees ADD COLUMN registration_no TEXT")
    if "experience_years" not in existing_cols:
        db.execute("ALTER TABLE employees ADD COLUMN experience_years REAL")
    if "paid_leaves_override" not in existing_cols:
        db.execute("ALTER TABLE employees ADD COLUMN paid_leaves_override INTEGER")
    if "unpaid_leaves_override" not in existing_cols:
        db.execute("ALTER TABLE employees ADD COLUMN unpaid_leaves_override INTEGER")
    if "total_leaves_override" not in existing_cols:
        db.execute("ALTER TABLE employees ADD COLUMN total_leaves_override INTEGER")
    db.commit()

    existing_user_cols = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
    if "email" not in existing_user_cols:
        db.execute("ALTER TABLE users ADD COLUMN email TEXT")
        db.commit()
    if "photo_path" not in existing_user_cols:
        db.execute("ALTER TABLE users ADD COLUMN photo_path TEXT")
        db.commit()

    existing_attendance_cols = {row["name"] for row in db.execute("PRAGMA table_info(attendance)")}
    if "check_in" not in existing_attendance_cols:
        db.execute("ALTER TABLE attendance ADD COLUMN check_in TEXT")
        db.commit()
    if "check_out" not in existing_attendance_cols:
        db.execute("ALTER TABLE attendance ADD COLUMN check_out TEXT")
        db.commit()

    existing_announcement_cols = {row["name"] for row in db.execute("PRAGMA table_info(announcements)")}
    if "updated_by" not in existing_announcement_cols:
        db.execute("ALTER TABLE announcements ADD COLUMN updated_by TEXT")
        db.commit()
    if "updated_at" not in existing_announcement_cols:
        db.execute("ALTER TABLE announcements ADD COLUMN updated_at TEXT")
        db.commit()

    existing_designation_cols = {row["name"] for row in db.execute("PRAGMA table_info(designations)")}
    if "department" not in existing_designation_cols:
        db.execute("ALTER TABLE designations ADD COLUMN department TEXT")
        db.commit()
        # Backfill: assign each of the known fixed designations to its department so the
        # designation dropdown can immediately filter by department instead of showing
        # everything. Any custom designation an admin added that isn't in the fixed list
        # is left with department = NULL, which means it shows up under every department
        # until an admin edits/re-adds it with a specific one.
        for des_name, dept_name in DESIGNATION_DEPARTMENT_MAP.items():
            db.execute(
                "UPDATE designations SET department = ? WHERE name = ? COLLATE NOCASE AND department IS NULL",
                (dept_name, des_name),
            )
        db.commit()

    existing = db.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
    if existing == 0:
        sample_employees = [
            ("Ananya Sharma", "ananya.sharma@gmail.com", "9876543210", "Engineering", "Frontend Developer", "Active", 65000, "2023-02-14"),
            ("Rohit Verma", "rohit.verma@gmail.com", "9812345678", "Human Resources", "HR Executive", "Active", 52000, "2022-08-01"),
            ("Priya Nair", "priya.nair@gmail.com", "9900112233", "Sales", "Sales Associate", "On Leave", 48000, "2021-11-20"),
        ]
        db.executemany(
            "INSERT INTO employees (name, email, phone, department, role, status, salary, join_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            sample_employees,
        )
        db.commit()

    # Seed departments / designations from the fixed lists the first time we see them.
    if db.execute("SELECT COUNT(*) FROM departments").fetchone()[0] == 0:
        db.executemany("INSERT OR IGNORE INTO departments (name) VALUES (?)", [(d,) for d in DEPARTMENTS])
        db.commit()

    if db.execute("SELECT COUNT(*) FROM designations").fetchone()[0] == 0:
        db.executemany(
            "INSERT OR IGNORE INTO designations (name, department) VALUES (?, ?)",
            [(r, DESIGNATION_DEPARTMENT_MAP.get(r)) for r in DESIGNATIONS],
        )
        db.commit()

    # Seed default login accounts (one per role) the first time.
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        # The demo "Employee" login needs its own employee record — it should
        # never borrow whichever employee happens to be first in the table.
        rs_employee = db.execute(
            "SELECT id FROM employees WHERE name = 'Ritika Subham'"
        ).fetchone()
        if rs_employee is None:
            cur = db.execute(
                "INSERT INTO employees (name, email, phone, department, role, status, salary, join_date) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("Ritika Subham", "ritika.subham@gmail.com", "9911223344",
                 "Human Resources", "HR Executive", "Active", 50000, date.today().isoformat()),
            )
            db.commit()
            rs_employee_id = cur.lastrowid
        else:
            rs_employee_id = rs_employee["id"]

        default_users = [
            ("Subham", "Thakur", "Subham Thakur", "Admin", None, "subham.admin@company.local"),
            ("Ritika", "Sarswat", "Ritika Sarswat", "HR", None, "ritika.hr@company.local"),
            ("SR", "RS", "Ritika Subham", "Employee", rs_employee_id, "ritika.subham@gmail.com"),
        ]
        for username, password, full_name, role, employee_id, email in default_users:
            db.execute(
                "INSERT INTO users (username, password_hash, full_name, role, employee_id, email) VALUES (?, ?, ?, ?, ?, ?)",
                (username, generate_password_hash(password), full_name, role, employee_id, email),
            )
        db.commit()

    # Backfill: any employee who doesn't already have a login account gets
    # one now (username = their name, password = 123). This covers
    # employees that were seeded/imported before login accounts existed,
    # and self-heals if it's ever run again.
    missing_logins = db.execute(
        "SELECT id, name FROM employees "
        "WHERE id NOT IN (SELECT employee_id FROM users WHERE employee_id IS NOT NULL)"
    ).fetchall()
    for emp in missing_logins:
        create_login_for_employee(db, emp["id"], emp["name"])
    if missing_logins:
        db.commit()

    # Backfill: existing employee-linked accounts created before the email
    # column existed should still get one, so "forgot password" works.
    db.execute(
        "UPDATE users SET email = (SELECT email FROM employees WHERE employees.id = users.employee_id) "
        "WHERE email IS NULL AND employee_id IS NOT NULL"
    )
    db.execute(
        "UPDATE users SET email = 'subham.admin@company.local' "
        "WHERE username = 'Subham' AND employee_id IS NULL AND (email IS NULL OR email = '')"
    )
    db.execute(
        "UPDATE users SET email = 'ritika.hr@company.local' "
        "WHERE username = 'Ritika' AND employee_id IS NULL AND (email IS NULL OR email = '')"
    )
    db.commit()

    # Backfill registration numbers for any employee rows that don't have one yet
    # (fresh seed rows, CSV imports, or older databases from before this column existed).
    # Runs last so it covers every seeded employee, including ones added above.
    # (Done in Python rather than SQL's printf()/format() so it works the same
    # way on both SQLite and Postgres.)
    for row in db.execute("SELECT id FROM employees WHERE registration_no IS NULL").fetchall():
        db.execute(
            "UPDATE employees SET registration_no = ? WHERE id = ?",
            (f"EMP{row['id']:04d}", row["id"]),
        )
    db.commit()

    # Ensure a single report_settings row exists so "Edit Reports" always has something to update.
    if db.execute("SELECT COUNT(*) FROM report_settings").fetchone()[0] == 0:
        db.execute(
            "INSERT INTO report_settings (id, notes, updated_by, updated_at) VALUES (1, '', NULL, NULL)"
        )
        db.commit()

    db.close()


def assign_registration_no(db, emp_id):
    """Give a newly-inserted employee row a human-friendly registration number."""
    registration_no = f"EMP{emp_id:04d}"
    db.execute("UPDATE employees SET registration_no = ? WHERE id = ?", (registration_no, emp_id))
    return registration_no


def get_department_names(db):
    rows = db.execute("SELECT name FROM departments ORDER BY name").fetchall()
    names = [row["name"] for row in rows]
    return names or list(DEPARTMENTS)


def get_designation_names(db):
    rows = db.execute("SELECT name FROM designations ORDER BY name").fetchall()
    names = [row["name"] for row in rows]
    return names or list(DESIGNATIONS)


def get_designations_with_department(db):
    """All designations along with the department they belong to (None = shows under
    every department). Used to render the designation dropdown so it can be filtered
    client-side to the currently selected department."""
    rows = db.execute("SELECT name, department FROM designations ORDER BY name").fetchall()
    if not rows:
        return [{"name": r, "department": DESIGNATION_DEPARTMENT_MAP.get(r)} for r in DESIGNATIONS]
    return [{"name": row["name"], "department": row["department"]} for row in rows]


def is_role_valid_for_department(db, department, role):
    """A designation is valid for a department if it's explicitly assigned to that
    department, or if it has no department assigned (shared/available everywhere)."""
    row = db.execute("SELECT department FROM designations WHERE name = ? COLLATE NOCASE", (role,)).fetchone()
    if row is None:
        return False
    return not row["department"] or row["department"] == department


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    db = get_db()

    if session.get("role") == "Employee":
        emp_id = current_employee_id()
        employee = db.execute("SELECT * FROM employees WHERE id = ?", (emp_id,)).fetchone() if emp_id else None
        my_leaves = db.execute(
            "SELECT * FROM leaves WHERE employee_id = ? ORDER BY applied_on DESC LIMIT 5", (emp_id,)
        ).fetchall() if emp_id else []
        month_prefix = date.today().isoformat()[:7]
        my_attendance = db.execute(
            "SELECT status, COUNT(*) c FROM attendance WHERE employee_id = ? AND date LIKE ? GROUP BY status",
            (emp_id, f"{month_prefix}%"),
        ).fetchall() if emp_id else []
        return render_template(
            "dashboard.html",
            employee_view=True,
            employee=employee,
            my_leaves=my_leaves,
            my_attendance={row["status"]: row["c"] for row in my_attendance},
        )

    employees = db.execute("SELECT * FROM employees ORDER BY id DESC").fetchall()
    total = len(employees)
    active = sum(1 for e in employees if e["status"] == "Active")
    on_leave = sum(1 for e in employees if e["status"] == "On Leave")
    departments = len({e["department"] for e in employees})
    pending_leaves = db.execute("SELECT COUNT(*) FROM leaves WHERE status = 'Pending'").fetchone()[0]

    today = date.today().isoformat()
    today_marked = db.execute("SELECT COUNT(*) FROM attendance WHERE date = ?", (today,)).fetchone()[0]
    today_present = db.execute(
        "SELECT COUNT(*) FROM attendance WHERE date = ? AND status = 'Present'", (today,)
    ).fetchone()[0]
    today_absent = db.execute(
        "SELECT COUNT(*) FROM attendance WHERE date = ? AND status = 'Absent'", (today,)
    ).fetchone()[0]
    today_attendance_pct = round((today_present / total) * 100) if total else 0

    month_prefix = date.today().isoformat()[:7]
    new_this_month = db.execute(
        "SELECT COUNT(*) FROM employees WHERE join_date LIKE ?", (f"{month_prefix}%",)
    ).fetchone()[0]

    # ---- chart data ----
    status_rows = db.execute(
        "SELECT status, COUNT(*) as count FROM employees GROUP BY status"
    ).fetchall()
    status_labels = [row["status"] for row in status_rows]
    status_counts = [row["count"] for row in status_rows]

    dept_rows = db.execute(
        "SELECT department, COUNT(*) as count FROM employees GROUP BY department ORDER BY department"
    ).fetchall()
    dept_labels = [row["department"] for row in dept_rows]
    dept_counts = [row["count"] for row in dept_rows]

    # last 6 months, oldest to newest, of marked "Present" attendance
    month_labels = []
    month_present_counts = []
    cursor_date = date.today().replace(day=1)
    months = []
    for i in range(5, -1, -1):
        y = cursor_date.year
        m = cursor_date.month - i
        while m <= 0:
            m += 12
            y -= 1
        months.append(f"{y:04d}-{m:02d}")
    for ym in months:
        count = db.execute(
            "SELECT COUNT(*) FROM attendance WHERE date LIKE ? AND status = 'Present'", (f"{ym}%",)
        ).fetchone()[0]
        month_labels.append(datetime.strptime(ym, "%Y-%m").strftime("%b"))
        month_present_counts.append(count)

    return render_template(
        "dashboard.html",
        employee_view=False,
        total=total,
        active=active,
        on_leave=on_leave,
        departments=departments,
        pending_leaves=pending_leaves,
        today_display=date.today().strftime("%d %b %Y"),
        today_marked=today_marked,
        today_absent=today_absent,
        today_attendance_pct=today_attendance_pct,
        new_this_month=new_this_month,
        recent=sorted(employees[:5], key=lambda e: (e["name"] or "").lower()),
        status_labels=status_labels,
        status_counts=status_counts,
        dept_labels=dept_labels,
        dept_counts=dept_counts,
        month_labels=month_labels,
        month_present_counts=month_present_counts,
    )


# ---------------------------------------------------------------------------
# Employee management
# ---------------------------------------------------------------------------
@app.route("/employees")
@login_required
@roles_required("Admin", "HR", "HR Manager")
def employee_list():
    db = get_db()
    q = request.args.get("q", "").strip()
    sort_filter = request.args.get("sort_filter", "").strip()

    department = request.args.get("department", "").strip()
    status = request.args.get("status", "").strip()
    new_this_month = request.args.get("new_this_month", "").strip()
    sort = ""

    if sort_filter.startswith("dept:"):
        department = sort_filter[len("dept:"):]
    elif sort_filter.startswith("status:"):
        status = sort_filter[len("status:"):]
    elif sort_filter:
        sort = sort_filter

    conditions = []
    params = []

    if q:
        like = f"%{q}%"
        conditions.append("(name LIKE ? OR department LIKE ? OR role LIKE ?)")
        params.extend([like, like, like])

    if department:
        conditions.append("department = ?")
        params.append(department)

    if status:
        conditions.append("status = ?")
        params.append(status)

    if new_this_month:
        month_prefix = date.today().isoformat()[:7]
        conditions.append("join_date LIKE ?")
        params.append(f"{month_prefix}%")

    sort_columns = {
        "name_asc": "name COLLATE NOCASE ASC",
        "name_desc": "name COLLATE NOCASE DESC",
        "join_date_asc": "join_date ASC",
        "join_date_desc": "join_date DESC",
    }
    order_by = sort_columns.get(sort, "id")

    query = "SELECT * FROM employees"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += f" ORDER BY {order_by}"

    employees = db.execute(query, params).fetchall()

    existing_departments = [
        row["department"] for row in db.execute(
            "SELECT DISTINCT department FROM employees ORDER BY department"
        ).fetchall()
    ]
    dropdown_departments = existing_departments or DEPARTMENTS

    return render_template(
        "employees.html",
        employees=employees,
        q=q,
        department=department,
        status=status,
        new_this_month=new_this_month,
        sort=sort,
        sort_filter=sort_filter,
        departments=dropdown_departments,
    )


@app.route("/employees/export")
@login_required
@roles_required("Admin", "HR", "HR Manager")
def export_employees():
    db = get_db()
    q = request.args.get("q", "").strip()
    department = request.args.get("department", "").strip()

    conditions = []
    params = []

    if q:
        like = f"%{q}%"
        conditions.append("(name LIKE ? OR department LIKE ? OR role LIKE ?)")
        params.extend([like, like, like])

    if department:
        conditions.append("department = ?")
        params.append(department)

    query = "SELECT id, name, email, phone, department, role, salary, status, join_date FROM employees"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id"

    rows = db.execute(query, params).fetchall()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["ID", "Name", "Email", "Phone", "Department", "Designation", "Salary", "Status", "Hire Date"])
    for r in rows:
        writer.writerow([
            r["id"],
            r["name"],
            r["email"],
            r["phone"] or "",
            r["department"],
            r["role"],
            r["salary"] if r["salary"] is not None else "",
            r["status"],
            r["join_date"],
        ])

    response = app.response_class(buffer.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=employees.csv"
    return response


@app.route("/employees/import", methods=["POST"])
@login_required
@roles_required("Admin", "HR", "HR Manager")
def import_employees():
    db = get_db()
    dept_names = get_department_names(db)
    role_names = get_designation_names(db)

    file = request.files.get("csv_file")
    if not file or file.filename == "":
        flash("Please choose a CSV file to import.")
        return redirect(url_for("employee_list"))

    try:
        content = file.stream.read().decode("utf-8-sig")
    except UnicodeDecodeError:
        flash("Could not read that file — please upload a UTF-8 CSV.")
        return redirect(url_for("employee_list"))

    reader = csv.DictReader(io.StringIO(content))
    if reader.fieldnames:
        reader.fieldnames = [(f or "").strip().lower() for f in reader.fieldnames]

    added = 0
    updated = 0
    skipped = 0

    for row in reader:
        row_id = (row.get("id") or "").strip()

        name = (row.get("name") or "").strip()
        if not name:
            first = (row.get("first_name") or "").strip()
            last = (row.get("last_name") or "").strip()
            name = f"{first} {last}".strip()

        email = (row.get("email") or "").strip()
        phone = (row.get("phone") or "").strip()
        department = (row.get("department") or "").strip()
        role = (row.get("role") or row.get("designation") or "").strip()
        status = (row.get("status") or "Active").strip() or "Active"
        salary_raw = (row.get("salary") or "").strip()
        hire_date = (row.get("hire_date") or row.get("join_date") or "").strip() or date.today().isoformat()

        if (
            not all([name, email, department, role])
            or department not in dept_names
            or role not in role_names
            or not is_role_valid_for_department(db, department, role)
        ):
            skipped += 1
            continue

        salary = None
        if salary_raw:
            try:
                salary = float(salary_raw)
            except ValueError:
                skipped += 1
                continue

        # Try to find an existing employee to update — by ID first (from a
        # previously exported CSV), then by email as a fallback match.
        existing = None
        if row_id.isdigit():
            existing = db.execute("SELECT id FROM employees WHERE id = ?", (int(row_id),)).fetchone()
        if not existing and email:
            existing = db.execute("SELECT id FROM employees WHERE email = ?", (email,)).fetchone()

        if existing:
            db.execute(
                "UPDATE employees SET name = ?, email = ?, phone = ?, department = ?, "
                "role = ?, status = ?, salary = ?, join_date = ? WHERE id = ?",
                (name, email, phone, department, role, status, salary, hire_date, existing["id"]),
            )
            updated += 1
            continue

        cur = db.execute(
            "INSERT INTO employees (name, email, phone, department, role, status, salary, join_date) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (name, email, phone, department, role, status, salary, hire_date),
        )
        assign_registration_no(db, cur.lastrowid)
        create_login_for_employee(db, cur.lastrowid, name)
        added += 1

    db.commit()
    log_audit("Employees imported via CSV", f"{added} added, {updated} updated, {skipped} skipped")
    flash(f"Imported: {added} added (login password: 123), {updated} updated, {skipped} skipped (missing or invalid data).")
    return redirect(url_for("employee_list"))


@app.route("/employees/add", methods=["GET", "POST"])
@login_required
@roles_required("Admin", "HR", "HR Manager")
def add_employee():
    db = get_db()
    dept_names = get_department_names(db)
    role_names = get_designation_names(db)
    role_rows = get_designations_with_department(db)

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        name = f"{first_name} {last_name}".strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        department = request.form.get("department", "").strip()
        role = request.form.get("role", "").strip()
        department_mode = request.form.get("department_mode", "existing").strip()
        role_mode = request.form.get("role_mode", "existing").strip()
        new_department = request.form.get("new_department", "").strip()
        new_role = request.form.get("new_role", "").strip()
        status = request.form.get("status", "Active")
        salary_raw = request.form.get("salary", "").strip()
        hire_date = request.form.get("hire_date", "").strip() or date.today().isoformat()
        experience_raw = request.form.get("experience_years", "").strip()

        def rerender():
            return render_template("add_employee.html", form=request.form, departments=dept_names, roles=role_names, role_rows=role_rows, today_display=date.today().strftime("%d %b %Y"))

        if not all([first_name, last_name, email]):
            flash("Please fill in all required fields.")
            return rerender()

        if len(first_name) > 16:
            flash("First name must be 16 characters or fewer.")
            return rerender()

        if not NAME_RE.match(first_name):
            flash("First name can only contain letters.")
            return rerender()

        if len(last_name) > 16:
            flash("Last name must be 16 characters or fewer.")
            return rerender()

        if not NAME_RE.match(last_name):
            flash("Last name can only contain letters.")
            return rerender()

        if department_mode == "new":
            if not new_department:
                flash("Please enter a name for the new department.")
                return rerender()
        elif not department:
            flash("Please select a department.")
            return rerender()

        if role_mode == "new":
            if not new_role:
                flash("Please enter a name for the new designation.")
                return rerender()
        elif not role:
            flash("Please select a designation.")
            return rerender()

        if not GMAIL_RE.match(email):
            flash("Please use a valid @gmail.com email address.")
            return rerender()

        # A custom "Other" department/designation belongs only to this person —
        # it's never inserted into the shared departments/designations tables,
        # so it never mixes into the dropdown options anyone else sees.
        if department_mode == "new":
            department = new_department
        elif department not in dept_names:
            flash("Please choose a valid department and designation from the list.")
            return rerender()

        if role_mode == "new":
            role = new_role
        elif role not in role_names or not is_role_valid_for_department(db, department, role):
            flash("Please choose a valid department and designation from the list.")
            return rerender()

        if phone and (not phone.isdigit() or len(phone) != 10):
            flash("Phone number must be exactly 10 digits.")
            return rerender()

        salary = None
        if salary_raw:
            try:
                salary = float(salary_raw)
            except ValueError:
                flash("Salary must be a number.")
                return rerender()

        experience_years = None
        if experience_raw:
            try:
                experience_years = float(experience_raw)
            except ValueError:
                flash("Experience must be a number.")
                return rerender()

        cur = db.execute(
            "INSERT INTO employees (name, email, phone, department, role, status, salary, experience_years, join_date) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name, email, phone, department, role, status, salary, experience_years, hire_date),
        )
        emp_id = cur.lastrowid
        assign_registration_no(db, emp_id)
        db.commit()
        username = create_login_for_employee(db, emp_id, name)
        db.commit()
        log_audit("Employee added", f"{name} ({department} / {role}), id={emp_id}")
        log_audit("Login account created", f"employee={name}, username={username}")
        flash(f"Employee added. Login created — username: {username}, password: 123")
        return redirect(url_for("employee_list"))

    return render_template(
        "add_employee.html",
        form={"hire_date": date.today().isoformat()},
        departments=dept_names,
        roles=role_names,
        role_rows=role_rows,
        today_display=date.today().strftime("%d %b %Y"),
    )


@app.route("/employees/<int:emp_id>")
@login_required
def employee_detail(emp_id):
    db = get_db()
    employee = db.execute("SELECT * FROM employees WHERE id = ?", (emp_id,)).fetchone()
    return render_template("employee_detail.html", employee=employee)


@app.route("/employees/<int:emp_id>/edit", methods=["GET", "POST"])
@login_required
@roles_required("Admin", "HR", "HR Manager")
def edit_employee(emp_id):
    db = get_db()
    employee = db.execute("SELECT * FROM employees WHERE id = ?", (emp_id,)).fetchone()

    if employee is None:
        flash("Employee not found.")
        return redirect(url_for("employee_list"))

    dept_names = get_department_names(db)
    role_names = get_designation_names(db)
    role_rows = get_designations_with_department(db)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        department = request.form.get("department", "").strip()
        role = request.form.get("role", "").strip()
        status = request.form.get("status", "Active")
        salary_raw = request.form.get("salary", "").strip()
        hire_date = request.form.get("hire_date", "").strip() or employee["join_date"]
        experience_raw = request.form.get("experience_years", "").strip()

        if not all([name, email, department, role]):
            flash("Please fill in all required fields.")
            return render_template("edit_employee.html", employee=employee, form=request.form, departments=dept_names, roles=role_names, role_rows=role_rows)

        if department not in dept_names or role not in role_names or not is_role_valid_for_department(db, department, role):
            flash("Please choose a valid department and designation from the list.")
            return render_template("edit_employee.html", employee=employee, form=request.form, departments=dept_names, roles=role_names, role_rows=role_rows)

        if phone and (not phone.isdigit() or len(phone) != 10):
            flash("Phone number must be exactly 10 digits.")
            return render_template("edit_employee.html", employee=employee, form=request.form, departments=dept_names, roles=role_names, role_rows=role_rows)

        salary = None
        if salary_raw:
            try:
                salary = float(salary_raw)
            except ValueError:
                flash("Salary must be a number.")
                return render_template("edit_employee.html", employee=employee, form=request.form, departments=dept_names, roles=role_names, role_rows=role_rows)

        experience_years = None
        if experience_raw:
            try:
                experience_years = float(experience_raw)
            except ValueError:
                flash("Experience must be a number.")
                return render_template("edit_employee.html", employee=employee, form=request.form, departments=dept_names, roles=role_names, role_rows=role_rows)

        db.execute(
            "UPDATE employees SET name = ?, email = ?, phone = ?, department = ?, role = ?, status = ?, "
            "salary = ?, experience_years = ?, join_date = ? WHERE id = ?",
            (name, email, phone, department, role, status, salary, experience_years, hire_date, emp_id),
        )
        db.commit()
        log_audit("Employee updated", f"{name}, id={emp_id}")
        return redirect(url_for("employee_detail", emp_id=emp_id))

    return render_template("edit_employee.html", employee=employee, form=dict(employee), departments=dept_names, roles=role_names, role_rows=role_rows)


@app.route("/employees/<int:emp_id>/delete", methods=["POST"])
@login_required
@roles_required("Admin", "HR", "HR Manager")
def delete_employee(emp_id):
    db = get_db()
    emp = db.execute("SELECT name FROM employees WHERE id = ?", (emp_id,)).fetchone()
    db.execute("DELETE FROM employees WHERE id = ?", (emp_id,))
    db.commit()
    flash("Employee deleted.")
    log_audit("Employee deleted", f"{emp['name'] if emp else emp_id}, id={emp_id}")
    return redirect(url_for("employee_list"))


# ---------------------------------------------------------------------------
# Department management
# ---------------------------------------------------------------------------
@app.route("/departments", methods=["GET", "POST"])
@login_required
@roles_required("Admin", "HR Manager")
def departments():
    db = get_db()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if not name:
            flash("Please enter a department name.")
        else:
            existing = db.execute("SELECT id FROM departments WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
            if existing:
                flash(f'"{name}" already exists.')
            else:
                db.execute("INSERT INTO departments (name) VALUES (?)", (name,))
                db.commit()
                log_audit("Department added", name)
        return redirect(url_for("departments"))

    department = request.args.get("department", "").strip()

    dept_query = "SELECT id, name FROM departments"
    dept_params = []
    if department:
        dept_query += " WHERE name = ?"
        dept_params.append(department)
    dept_query += " ORDER BY name"

    dept_rows = db.execute(dept_query, dept_params).fetchall()
    counts = {
        row["department"]: row["count"]
        for row in db.execute("SELECT department, COUNT(*) as count FROM employees GROUP BY department").fetchall()
    }
    salaries = {
        row["department"]: row["total"]
        for row in db.execute("SELECT department, SUM(salary) as total FROM employees GROUP BY department").fetchall()
    }

    members = {}
    for row in db.execute("SELECT department, name FROM employees ORDER BY name").fetchall():
        members.setdefault(row["department"], []).append(row["name"])

    # Only departments that actually have at least one employee are shown —
    # a department defined in Settings with nobody assigned yet stays hidden
    # here until someone joins it.
    dept_list = [
        {
            "id": row["id"],
            "name": row["name"],
            "count": counts.get(row["name"], 0),
            "total_salary": salaries.get(row["name"]) or 0,
            "members": members.get(row["name"], []),
        }
        for row in dept_rows
        if counts.get(row["name"], 0) > 0
    ]

    all_dept_names = [
        row["name"] for row in db.execute("SELECT name FROM departments ORDER BY name").fetchall()
        if counts.get(row["name"], 0) > 0
    ]

    return render_template(
        "departments.html",
        departments=dept_list,
        all_departments=all_dept_names,
        selected_department=department,
    )


@app.route("/departments/<int:dept_id>/delete", methods=["POST"])
@login_required
@roles_required("Admin", "HR Manager")
def delete_department(dept_id):
    db = get_db()
    dept = db.execute("SELECT name FROM departments WHERE id = ?", (dept_id,)).fetchone()
    if dept is not None:
        in_use = db.execute("SELECT COUNT(*) FROM employees WHERE department = ?", (dept["name"],)).fetchone()[0]
        if in_use:
            flash(f'Can\'t delete "{dept["name"]}" - {in_use} employee(s) still assigned to it.')
        else:
            db.execute("DELETE FROM departments WHERE id = ?", (dept_id,))
            db.commit()
            flash(f'Deleted "{dept["name"]}".')
            log_audit("Department deleted", dept["name"])
    return redirect(url_for("departments"))


# ---------------------------------------------------------------------------
# Designation management
# ---------------------------------------------------------------------------
@app.route("/designations", methods=["GET", "POST"])
@login_required
@roles_required("Admin", "HR Manager")
def designations():
    db = get_db()
    dept_names = get_department_names(db)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        department = request.form.get("department", "").strip()
        if not name:
            flash("Please enter a designation name.")
        elif not department or department not in dept_names:
            flash("Please choose which department this designation belongs to.")
        else:
            existing = db.execute("SELECT id FROM designations WHERE name = ? COLLATE NOCASE", (name,)).fetchone()
            if existing:
                flash(f'"{name}" already exists.')
            else:
                db.execute("INSERT INTO designations (name, department) VALUES (?, ?)", (name, department))
                db.commit()
                log_audit("Designation added", f"{name} ({department})")
        return redirect(url_for("designations"))

    rows = db.execute("SELECT id, name, department FROM designations ORDER BY name").fetchall()
    counts = {
        row["role"]: row["count"]
        for row in db.execute("SELECT role, COUNT(*) as count FROM employees GROUP BY role").fetchall()
    }
    designation_list = [
        {"id": row["id"], "name": row["name"], "department": row["department"], "count": counts.get(row["name"], 0)}
        for row in rows
    ]

    return render_template("designations.html", designations=designation_list, departments=dept_names)


@app.route("/designations/<int:des_id>/delete", methods=["POST"])
@login_required
@roles_required("Admin", "HR Manager")
def delete_designation(des_id):
    db = get_db()
    des = db.execute("SELECT name FROM designations WHERE id = ?", (des_id,)).fetchone()
    if des is not None:
        in_use = db.execute("SELECT COUNT(*) FROM employees WHERE role = ?", (des["name"],)).fetchone()[0]
        if in_use:
            flash(f'Can\'t delete "{des["name"]}" - {in_use} employee(s) still hold that designation.')
        else:
            db.execute("DELETE FROM designations WHERE id = ?", (des_id,))
            db.commit()
            flash(f'Deleted "{des["name"]}".')
            log_audit("Designation deleted", des["name"])
    return redirect(url_for("designations"))


# ---------------------------------------------------------------------------
# Attendance
# ---------------------------------------------------------------------------
@app.route("/attendance/update/<int:emp_id>", methods=["POST"])
@login_required
def attendance_update_one(emp_id):
    is_staff = session.get("role") in ("Admin", "HR Manager")
    payload = request.get_json(silent=True) or {}
    selected_date = payload.get("date") or date.today().isoformat()

    if not is_staff:
        # A plain Employee account may only mark their own attendance, and only
        # for today — they can't touch anyone else's record or edit past dates.
        if current_employee_id() != emp_id:
            return jsonify({"ok": False, "error": "forbidden"}), 403
        if selected_date != date.today().isoformat():
            return jsonify({"ok": False, "error": "forbidden"}), 403

    status = payload.get("status")
    if status not in ATTENDANCE_STATUSES:
        return jsonify({"ok": False, "error": "invalid status"}), 400

    db = get_db()
    existing = db.execute(
        "SELECT check_in FROM attendance WHERE employee_id = ? AND date = ?",
        (emp_id, selected_date),
    ).fetchone()
    check_in = existing["check_in"] if existing and existing["check_in"] else None
    if status == "Present" and not check_in:
        check_in = datetime.now().strftime("%H:%M")

    db.execute(
        "INSERT INTO attendance (employee_id, date, status, check_in) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(employee_id, date) DO UPDATE SET status = excluded.status, "
        "check_in = COALESCE(attendance.check_in, excluded.check_in)",
        (emp_id, selected_date, status, check_in),
    )
    sync_employee_status_from_attendance(db, emp_id, status, selected_date)
    db.commit()
    action = "Attendance self-marked" if not is_staff else "Attendance updated"
    log_audit(action, f"employee_id={emp_id}, date={selected_date}, status={status}")
    return jsonify({"ok": True, "status": status, "check_in": check_in})


@app.route("/attendance", methods=["GET", "POST"])
@login_required
def attendance():
    db = get_db()
    is_staff = session.get("role") in ("Admin", "HR Manager")
    selected_date = request.form.get("date") or request.args.get("date") or date.today().isoformat()

    if request.method == "POST":
        if is_staff:
            employees = db.execute("SELECT id FROM employees").fetchall()
        else:
            # A plain Employee account can only save their own attendance,
            # and only for today's date — never someone else's, never a past date.
            emp_id = current_employee_id()
            if not emp_id or selected_date != date.today().isoformat():
                flash("You don't have permission to do that.")
                return redirect(url_for("attendance"))
            employees = db.execute("SELECT id FROM employees WHERE id = ?", (emp_id,)).fetchall()
        now_time = datetime.now().strftime("%H:%M")
        for emp in employees:
            status = request.form.get(f"status_{emp['id']}")
            if status:
                existing = db.execute(
                    "SELECT check_in FROM attendance WHERE employee_id = ? AND date = ?",
                    (emp["id"], selected_date),
                ).fetchone()
                # Auto-stamp a check-in time the first time someone is marked Present,
                # without clobbering a check-in that's already been recorded.
                check_in = existing["check_in"] if existing and existing["check_in"] else None
                if status == "Present" and not check_in:
                    check_in = now_time
                db.execute(
                    "INSERT INTO attendance (employee_id, date, status, check_in) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(employee_id, date) DO UPDATE SET status = excluded.status, "
                    "check_in = COALESCE(attendance.check_in, excluded.check_in)",
                    (emp["id"], selected_date, status, check_in),
                )
                sync_employee_status_from_attendance(db, emp["id"], status, selected_date)
        db.commit()
        flash(f"Attendance saved for {selected_date}.")
        log_audit("Attendance saved", f"date={selected_date}")
        return redirect(url_for("attendance", date=selected_date))

    if is_staff:
        employees = db.execute("SELECT * FROM employees ORDER BY name").fetchall()
    else:
        emp_id = current_employee_id()
        employees = db.execute("SELECT * FROM employees WHERE id = ?", (emp_id,)).fetchall() if emp_id else []

    marked = {
        row["employee_id"]: row["status"]
        for row in db.execute("SELECT employee_id, status FROM attendance WHERE date = ?", (selected_date,)).fetchall()
    }

    roster = [{"employee": e, "status": marked.get(e["id"], "Present")} for e in employees]

    summary = {s: 0 for s in ATTENDANCE_STATUSES}
    for entry in roster:
        summary[entry["status"]] = summary.get(entry["status"], 0) + 1

    return render_template(
        "attendance.html",
        roster=roster,
        selected_date=selected_date,
        today=date.today().isoformat(),
        statuses=ATTENDANCE_STATUSES,
        summary=summary,
        is_staff=is_staff,
    )


@app.route("/attendance/present")
@login_required
def attendance_present():
    db = get_db()
    is_staff = session.get("role") in ("Admin", "HR Manager")
    selected_date = request.args.get("date") or date.today().isoformat()

    if is_staff:
        rows = db.execute(
            "SELECT e.id, e.name, e.department, e.role, a.status, a.check_in, a.check_out "
            "FROM attendance a JOIN employees e ON e.id = a.employee_id "
            "WHERE a.date = ? AND a.status = 'Present' ORDER BY e.name",
            (selected_date,),
        ).fetchall()
    else:
        emp_id = current_employee_id()
        rows = db.execute(
            "SELECT e.id, e.name, e.department, e.role, a.status, a.check_in, a.check_out "
            "FROM attendance a JOIN employees e ON e.id = a.employee_id "
            "WHERE a.date = ? AND a.status = 'Present' AND e.id = ? ORDER BY e.name",
            (selected_date, emp_id),
        ).fetchall() if emp_id else []

    return render_template(
        "attendance_present.html",
        rows=rows,
        selected_date=selected_date,
        today=date.today().isoformat(),
        is_staff=is_staff,
    )


@app.route("/attendance/present/<int:emp_id>/checkout", methods=["POST"])
@login_required
def attendance_checkout(emp_id):
    db = get_db()
    is_staff = session.get("role") in ("Admin", "HR Manager")
    selected_date = request.form.get("date") or date.today().isoformat()

    if not is_staff and current_employee_id() != emp_id:
        flash("You don't have permission to do that.")
        return redirect(url_for("attendance_present", date=selected_date))

    now_time = datetime.now().strftime("%H:%M")
    db.execute(
        "UPDATE attendance SET check_out = ? WHERE employee_id = ? AND date = ?",
        (now_time, emp_id, selected_date),
    )
    db.commit()
    log_audit("Checked out", f"employee_id={emp_id}, date={selected_date}, time={now_time}")
    return redirect(url_for("attendance_present", date=selected_date))


# ---------------------------------------------------------------------------
# Leave management
# ---------------------------------------------------------------------------
@app.route("/leaves", methods=["GET"])
@login_required
def leave_list():
    db = get_db()
    is_staff = session.get("role") in ("Admin", "HR Manager")

    if is_staff:
        status = request.args.get("status", "").strip()
        query = (
            "SELECT leaves.*, employees.name as employee_name, employees.department as department "
            "FROM leaves JOIN employees ON employees.id = leaves.employee_id"
        )
        params = []
        if status:
            query += " WHERE leaves.status = ?"
            params.append(status)
        query += " ORDER BY leaves.applied_on DESC"
        leaves = db.execute(query, params).fetchall()
    else:
        emp_id = current_employee_id()
        leaves = db.execute(
            "SELECT leaves.*, employees.name as employee_name, employees.department as department "
            "FROM leaves JOIN employees ON employees.id = leaves.employee_id "
            "WHERE leaves.employee_id = ? ORDER BY leaves.applied_on DESC",
            (emp_id,),
        ).fetchall() if emp_id else []
        status = ""

    return render_template("leaves.html", leaves=leaves, is_staff=is_staff, statuses=LEAVE_STATUSES, selected_status=status)


@app.route("/leaves/apply", methods=["GET", "POST"])
@login_required
def apply_leave():
    db = get_db()
    emp_id = current_employee_id()

    # Staff can file leave on behalf of any employee; a plain Employee account
    # can only file leave for themselves.
    is_staff = session.get("role") in ("Admin", "HR Manager")
    employees = db.execute("SELECT id, name FROM employees ORDER BY name").fetchall() if is_staff else []

    if request.method == "POST":
        target_emp_id = int(request.form.get("employee_id")) if is_staff else emp_id
        leave_type = request.form.get("leave_type", "").strip()
        start_date = request.form.get("start_date", "").strip()
        end_date = request.form.get("end_date", "").strip()
        reason = request.form.get("reason", "").strip()

        if not target_emp_id:
            flash("No employee account is linked to your login. Contact an administrator.")
            return redirect(url_for("leave_list"))

        if not all([leave_type, start_date, end_date]) or leave_type not in LEAVE_TYPES:
            flash("Please fill in leave type, start date, and end date.")
            return render_template("apply_leave.html", employees=employees, is_staff=is_staff, leave_types=LEAVE_TYPES, form=request.form)

        if end_date < start_date:
            flash("End date can't be before the start date.")
            return render_template("apply_leave.html", employees=employees, is_staff=is_staff, leave_types=LEAVE_TYPES, form=request.form)

        # An Admin filing leave on someone's behalf doesn't need a separate
        # approval step — it's approved the moment it's submitted. Anyone else
        # (including HR Manager, or an employee filing for themselves) still
        # goes through the normal Pending -> Approve/Reject flow.
        auto_approve = session.get("role") == "Admin"
        status = "Approved" if auto_approve else "Pending"
        today_iso = date.today().isoformat()

        db.execute(
            "INSERT INTO leaves (employee_id, leave_type, start_date, end_date, reason, status, applied_on, decided_by, decided_on) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                target_emp_id, leave_type, start_date, end_date, reason, status, today_iso,
                session.get("username") if auto_approve else None,
                today_iso if auto_approve else None,
            ),
        )

        if auto_approve:
            mark_attendance_for_leave(db, target_emp_id, start_date, end_date)
            if start_date <= today_iso <= end_date:
                db.execute("UPDATE employees SET status = 'On Leave' WHERE id = ?", (target_emp_id,))

        db.commit()
        flash("Leave application submitted and auto-approved." if auto_approve else "Leave application submitted.")
        log_audit("Leave applied", f"employee_id={target_emp_id}, {leave_type} {start_date} to {end_date}" + (", auto-approved" if auto_approve else ""))
        return redirect(url_for("leave_list"))

    return render_template("apply_leave.html", employees=employees, is_staff=is_staff, leave_types=LEAVE_TYPES, form={})


@app.route("/leaves/<int:leave_id>/decide", methods=["POST"])
@login_required
@roles_required("Admin", "HR Manager")
def decide_leave(leave_id):
    db = get_db()
    decision = request.form.get("decision")
    if decision not in ("Approved", "Rejected"):
        flash("Invalid decision.")
        return redirect(url_for("leave_list"))

    leave = db.execute("SELECT * FROM leaves WHERE id = ?", (leave_id,)).fetchone()
    if leave is None:
        flash("Leave request not found.")
        return redirect(url_for("leave_list"))

    db.execute(
        "UPDATE leaves SET status = ?, decided_by = ?, decided_on = ? WHERE id = ?",
        (decision, session.get("username"), date.today().isoformat(), leave_id),
    )

    # Reflect an approved leave on attendance for every day it covers, and on
    # the employee's status if it covers today.
    if decision == "Approved":
        mark_attendance_for_leave(db, leave["employee_id"], leave["start_date"], leave["end_date"])
        today = date.today().isoformat()
        if leave["start_date"] <= today <= leave["end_date"]:
            db.execute("UPDATE employees SET status = 'On Leave' WHERE id = ?", (leave["employee_id"],))

    db.commit()
    flash(f"Leave request {decision.lower()}.")
    log_audit(f"Leave {decision.lower()}", f"leave_id={leave_id}, employee_id={leave['employee_id']}")
    return redirect(url_for("leave_list"))


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
@app.route("/reports")
@login_required
@roles_required("Admin", "HR Manager")
def reports():
    db = get_db()

    dept_strength = db.execute(
        "SELECT department, COUNT(*) as count FROM employees GROUP BY department ORDER BY department"
    ).fetchall()

    status_breakdown = db.execute(
        "SELECT status, COUNT(*) as count FROM employees GROUP BY status"
    ).fetchall()

    month_prefix = date.today().isoformat()[:7]
    attendance_this_month = db.execute(
        "SELECT employees.name as name, employees.department as department, "
        "SUM(CASE WHEN attendance.status = 'Present' THEN 1 ELSE 0 END) as present_days, "
        "COUNT(attendance.id) as marked_days "
        "FROM employees LEFT JOIN attendance ON attendance.employee_id = employees.id AND attendance.date LIKE ? "
        "GROUP BY employees.id ORDER BY employees.name",
        (f"{month_prefix}%",),
    ).fetchall()

    leave_summary = db.execute(
        "SELECT status, COUNT(*) as count FROM leaves GROUP BY status"
    ).fetchall()

    leave_by_type = db.execute(
        "SELECT leave_type, COUNT(*) as count FROM leaves WHERE status = 'Approved' GROUP BY leave_type"
    ).fetchall()

    total_salary = db.execute("SELECT SUM(salary) as total FROM employees").fetchone()["total"] or 0

    report_notes_row = db.execute("SELECT notes, updated_by, updated_at FROM report_settings WHERE id = 1").fetchone()

    return render_template(
        "reports.html",
        dept_strength=dept_strength,
        status_breakdown=status_breakdown,
        attendance_this_month=attendance_this_month,
        month_label=month_prefix,
        leave_summary=leave_summary,
        leave_by_type=leave_by_type,
        total_salary=total_salary,
        report_notes=report_notes_row["notes"] if report_notes_row else "",
        report_notes_updated_by=report_notes_row["updated_by"] if report_notes_row else None,
        report_notes_updated_at=report_notes_row["updated_at"] if report_notes_row else None,
    )


@app.route("/reports/edit", methods=["GET", "POST"])
@login_required
@roles_required("Admin")
def edit_reports():
    db = get_db()

    if request.method == "POST":
        if request.form.get("save_leaves"):
            emp_ids = request.form.getlist("emp_id")
            for emp_id in emp_ids:
                def _parse(field):
                    raw = request.form.get(f"{field}_{emp_id}", "").strip()
                    if raw == "":
                        return None
                    try:
                        return int(raw)
                    except ValueError:
                        return None

                paid_val = _parse("paid")
                unpaid_val = _parse("unpaid")
                total_val = _parse("total")
                db.execute(
                    "UPDATE employees SET paid_leaves_override = ?, unpaid_leaves_override = ?, "
                    "total_leaves_override = ? WHERE id = ?",
                    (paid_val, unpaid_val, total_val, emp_id),
                )
            db.commit()
            log_audit("Employee leave/salary report edited", f"by={session.get('username')}")
            flash("Employee leave report updated.")
            return redirect(url_for("edit_reports"))

        notes = request.form.get("notes", "").strip()
        db.execute(
            "UPDATE report_settings SET notes = ?, updated_by = ?, updated_at = ? WHERE id = 1",
            (notes, session.get("username"), datetime.now().strftime("%Y-%m-%d %H:%M")),
        )
        db.commit()
        log_audit("Report notes updated", f"by={session.get('username')}")
        flash("Report notes updated.")
        return redirect(url_for("reports"))

    row = db.execute("SELECT notes, updated_by, updated_at FROM report_settings WHERE id = 1").fetchone()

    employees = db.execute(
        "SELECT id, registration_no, name, department, salary, "
        "paid_leaves_override, unpaid_leaves_override, total_leaves_override "
        "FROM employees ORDER BY name"
    ).fetchall()
    leave_rows = db.execute(
        "SELECT employee_id, leave_type, "
        "SUM(julianday(end_date) - julianday(start_date) + 1) as days "
        "FROM leaves WHERE status = 'Approved' GROUP BY employee_id, leave_type"
    ).fetchall()

    leave_totals = {}
    for lr in leave_rows:
        emp_totals = leave_totals.setdefault(lr["employee_id"], {"paid": 0, "unpaid": 0})
        days = lr["days"] or 0
        if lr["leave_type"] == "Unpaid Leave":
            emp_totals["unpaid"] += days
        else:
            emp_totals["paid"] += days

    employee_reports = []
    for emp in employees:
        totals = leave_totals.get(emp["id"], {"paid": 0, "unpaid": 0})
        computed_paid = int(totals["paid"])
        computed_unpaid = int(totals["unpaid"])

        # A manually saved value (override) wins over the computed value.
        paid_days = emp["paid_leaves_override"] if emp["paid_leaves_override"] is not None else computed_paid
        unpaid_days = emp["unpaid_leaves_override"] if emp["unpaid_leaves_override"] is not None else computed_unpaid
        total_days = emp["total_leaves_override"] if emp["total_leaves_override"] is not None else (paid_days + unpaid_days)

        employee_reports.append({
            "id": emp["id"],
            "registration_no": emp["registration_no"],
            "name": emp["name"],
            "department": emp["department"],
            "paid_leaves": paid_days,
            "unpaid_leaves": unpaid_days,
            "total_leaves": total_days,
            "salary": emp["salary"] or 0,
        })

    return render_template(
        "edit_reports.html",
        notes=row["notes"] if row else "",
        updated_by=row["updated_by"] if row else None,
        updated_at=row["updated_at"] if row else None,
        employee_reports=employee_reports,
    )


# ---------------------------------------------------------------------------
# Audit logs
# ---------------------------------------------------------------------------
@app.route("/audit-logs")
@login_required
@roles_required("Admin")
def audit_logs():
    db = get_db()
    action_filter = request.args.get("action", "").strip()

    query = "SELECT * FROM audit_log"
    params = []
    if action_filter:
        query += " WHERE action LIKE ?"
        params.append(f"%{action_filter}%")
    query += " ORDER BY id DESC LIMIT 300"

    logs = db.execute(query, params).fetchall()
    return render_template("audit_log.html", logs=logs, action_filter=action_filter)


@app.route("/audit-logs/clear", methods=["POST"])
@login_required
@roles_required("Admin")
def clear_audit_logs():
    db = get_db()
    db.execute("DELETE FROM audit_log")
    db.commit()
    log_audit("Audit logs cleared")
    flash("Audit logs cleared.")
    return redirect(url_for("audit_logs"))


# ---------------------------------------------------------------------------
# Announcements
# ---------------------------------------------------------------------------
@app.route("/announcements")
@login_required
def announcements():
    db = get_db()
    rows = db.execute("SELECT * FROM announcements ORDER BY id DESC").fetchall()
    can_post = session.get("role") in ("Admin", "HR", "HR Manager")

    # Opening the list marks every announcement in it as seen for this user,
    # so the unread badge count in the navbar drops right away.
    user_id = session.get("user_id")
    if user_id and rows:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.executemany(
            "INSERT OR IGNORE INTO announcement_reads (user_id, announcement_id, read_at) VALUES (?, ?, ?)",
            [(user_id, r["id"], now) for r in rows],
        )
        db.commit()

    return render_template("announcements.html", announcements=rows, can_post=can_post)


@app.route("/announcements/post", methods=["GET", "POST"])
@login_required
@roles_required("Admin", "HR", "HR Manager")
def post_announcement():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        message = request.form.get("message", "").strip()

        if not title or not message:
            flash("Please fill in both the title and the message.")
            return render_template("post_announcement.html", form=request.form)

        db = get_db()
        db.execute(
            "INSERT INTO announcements (title, message, posted_by, posted_by_role, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (title, message, session.get("username"), session.get("role"), datetime.now().strftime("%Y-%m-%d %H:%M")),
        )
        db.commit()
        log_audit("Announcement posted", f"title={title}")
        flash("Announcement posted.")
        return redirect(url_for("announcements"))

    return render_template("post_announcement.html", form={})


@app.route("/announcements/<int:ann_id>/edit", methods=["GET", "POST"])
@login_required
@roles_required("Admin", "HR", "HR Manager")
def edit_announcement(ann_id):
    db = get_db()
    ann = db.execute("SELECT * FROM announcements WHERE id = ?", (ann_id,)).fetchone()
    if ann is None:
        flash("Announcement not found.")
        return redirect(url_for("announcements"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        message = request.form.get("message", "").strip()

        if not title or not message:
            flash("Please fill in both the title and the message.")
            return render_template("post_announcement.html", form=request.form, editing=True, ann_id=ann_id)

        db.execute(
            "UPDATE announcements SET title = ?, message = ?, updated_by = ?, updated_at = ? WHERE id = ?",
            (title, message, session.get("username"), datetime.now().strftime("%Y-%m-%d %H:%M"), ann_id),
        )
        db.commit()
        log_audit("Announcement edited", f"title={title}, id={ann_id}")
        flash("Announcement updated.")
        return redirect(url_for("announcements"))

    return render_template(
        "post_announcement.html",
        form={"title": ann["title"], "message": ann["message"]},
        editing=True,
        ann_id=ann_id,
    )


@app.route("/announcements/<int:ann_id>/delete", methods=["POST"])
@login_required
@roles_required("Admin", "HR", "HR Manager")
def delete_announcement(ann_id):
    db = get_db()
    reason = request.form.get("reason", "").strip()
    if not reason:
        flash("Please provide a reason for deleting this announcement.")
        return redirect(url_for("announcements"))

    ann = db.execute("SELECT title FROM announcements WHERE id = ?", (ann_id,)).fetchone()
    db.execute("DELETE FROM announcements WHERE id = ?", (ann_id,))
    db.commit()
    log_audit("Announcement deleted", f"{ann['title'] if ann else ann_id}, id={ann_id}, reason={reason}")
    flash("Announcement deleted.")
    return redirect(url_for("announcements"))


# ---------------------------------------------------------------------------
# Self-signup (public "Create Account" flow + Admin approval)
# ---------------------------------------------------------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    db = get_db()
    dept_names = get_department_names(db)
    role_names = get_designation_names(db)
    role_rows = get_designations_with_department(db)

    if request.method == "POST":
        form = request.form
        username = form.get("username", "").strip()
        password = form.get("password", "")
        confirm_password = form.get("confirm_password", "")
        first_name = form.get("first_name", "").strip()
        last_name = form.get("last_name", "").strip()
        email = form.get("email", "").strip()
        phone = form.get("phone", "").strip()
        department = form.get("department", "").strip()
        role = form.get("role", "").strip()
        department_mode = form.get("department_mode", "existing").strip()
        role_mode = form.get("role_mode", "existing").strip()
        new_department = form.get("new_department", "").strip()
        new_role = form.get("new_role", "").strip()
        experience_raw = form.get("experience_years", "").strip()
        hire_date = form.get("hire_date", "").strip() or date.today().isoformat()

        def rerender():
            return render_template("signup.html", form=form, departments=dept_names, roles=role_names, role_rows=role_rows)

        if not all([username, password, first_name, last_name, email]):
            flash("Please fill in all required fields.")
            return rerender()

        if len(first_name) > 16:
            flash("First name must be 16 characters or fewer.")
            return rerender()

        if not NAME_RE.match(first_name):
            flash("First name can only contain letters.")
            return rerender()

        if len(last_name) > 16:
            flash("Last name must be 16 characters or fewer.")
            return rerender()

        if not NAME_RE.match(last_name):
            flash("Last name can only contain letters.")
            return rerender()

        if len(username) > 32:
            flash("Username must be 32 characters or fewer.")
            return rerender()

        if department_mode == "new":
            if not new_department:
                flash("Please enter a name for the new department.")
                return rerender()
        elif not department:
            flash("Please select a department.")
            return rerender()

        if role_mode == "new":
            if not new_role:
                flash("Please enter a name for the new designation.")
                return rerender()
        elif not role:
            flash("Please select a designation.")
            return rerender()

        if password != confirm_password:
            flash("Passwords do not match.")
            return rerender()

        if len(password) < 4:
            flash("Password must be at least 4 characters.")
            return rerender()

        if not GMAIL_RE.match(email):
            flash("Please sign up with a valid @gmail.com email address.")
            return rerender()

        # A custom "Other" department/designation belongs only to this person —
        # it's never inserted into the shared departments/designations tables,
        # so it never mixes into the dropdown options anyone else sees.
        if department_mode == "new":
            department = new_department
        elif department not in dept_names:
            flash("Please choose a valid department and designation from the list.")
            return rerender()

        if role_mode == "new":
            role = new_role
        elif role not in role_names or not is_role_valid_for_department(db, department, role):
            flash("Please choose a valid department and designation from the list.")
            return rerender()

        if phone and (not phone.isdigit() or len(phone) != 10):
            flash("Phone number must be exactly 10 digits.")
            return rerender()

        experience_years = None
        if experience_raw:
            try:
                experience_years = float(experience_raw)
            except ValueError:
                flash("Experience must be a number.")
                return rerender()

        username_taken = db.execute(
            "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,)
        ).fetchone()
        request_pending = db.execute(
            "SELECT 1 FROM signup_requests WHERE username = ? COLLATE NOCASE AND status = 'Pending'",
            (username,),
        ).fetchone()
        if username_taken or request_pending:
            flash("That username is already taken. Please choose another.")
            return rerender()

        db.execute(
            "INSERT INTO signup_requests (username, password_hash, first_name, last_name, email, phone, "
            "department, role, experience_years, hire_date, status, requested_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?)",
            (
                username,
                generate_password_hash(password),
                first_name,
                last_name,
                email,
                phone,
                department,
                role,
                experience_years,
                hire_date,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        db.commit()
        flash("Your account request has been submitted. An admin will review it and you'll be able to sign in once it's approved.")
        return redirect(url_for("login"))

    return render_template(
        "signup.html",
        form={"hire_date": date.today().isoformat()},
        departments=dept_names,
        roles=role_names,
        role_rows=role_rows,
    )


@app.route("/signup-requests")
@login_required
@roles_required("Admin")
def signup_requests():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM signup_requests ORDER BY (status = 'Pending') DESC, id DESC"
    ).fetchall()
    return render_template("signup_requests.html", requests=rows)


@app.route("/signup-requests/<int:req_id>")
@login_required
@roles_required("Admin")
def signup_request_detail(req_id):
    db = get_db()
    req = db.execute("SELECT * FROM signup_requests WHERE id = ?", (req_id,)).fetchone()
    if req is None:
        flash("Request not found.")
        return redirect(url_for("signup_requests"))
    return render_template("signup_request_detail.html", req=req)


@app.route("/signup-requests/<int:req_id>/approve", methods=["POST"])
@login_required
@roles_required("Admin")
def approve_signup_request(req_id):
    db = get_db()
    req = db.execute("SELECT * FROM signup_requests WHERE id = ?", (req_id,)).fetchone()
    if req is None:
        flash("Request not found.")
        return redirect(url_for("signup_requests"))
    if req["status"] != "Pending":
        flash("This request has already been decided.")
        return redirect(url_for("signup_requests"))

    name = f"{req['first_name']} {req['last_name']}".strip()
    cur = db.execute(
        "INSERT INTO employees (name, email, phone, department, role, status, experience_years, join_date) "
        "VALUES (?, ?, ?, ?, ?, 'Active', ?, ?)",
        (
            name,
            req["email"],
            req["phone"],
            req["department"],
            req["role"],
            req["experience_years"],
            req["hire_date"] or date.today().isoformat(),
        ),
    )
    emp_id = cur.lastrowid
    assign_registration_no(db, emp_id)

    username = ensure_unique_username(db, req["username"])
    db.execute(
        "INSERT INTO users (username, password_hash, full_name, role, employee_id, email) "
        "VALUES (?, ?, ?, 'Employee', ?, ?)",
        (username, req["password_hash"], name, emp_id, req["email"]),
    )

    db.execute(
        "UPDATE signup_requests SET status = 'Approved', decided_by = ?, decided_at = ?, employee_id = ? WHERE id = ?",
        (session.get("username"), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), emp_id, req_id),
    )
    db.commit()
    log_audit("Signup request approved", f"{name}, username={username}, id={req_id}")
    flash(f"Account approved for {name}. They can now sign in with username: {username}")
    return redirect(url_for("signup_requests"))


@app.route("/signup-requests/<int:req_id>/reject", methods=["POST"])
@login_required
@roles_required("Admin")
def reject_signup_request(req_id):
    db = get_db()
    req = db.execute("SELECT * FROM signup_requests WHERE id = ?", (req_id,)).fetchone()
    if req is None:
        flash("Request not found.")
        return redirect(url_for("signup_requests"))
    if req["status"] != "Pending":
        flash("This request has already been decided.")
        return redirect(url_for("signup_requests"))

    db.execute(
        "UPDATE signup_requests SET status = 'Rejected', decided_by = ?, decided_at = ? WHERE id = ?",
        (session.get("username"), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), req_id),
    )
    db.commit()
    log_audit("Signup request rejected", f"username={req['username']}, id={req_id}")
    flash("Request rejected. No account was created.")
    return redirect(url_for("signup_requests"))


@app.route("/signup-requests/<int:req_id>/delete", methods=["POST"])
@login_required
@roles_required("Admin")
def delete_signup_request(req_id):
    db = get_db()
    req = db.execute("SELECT * FROM signup_requests WHERE id = ?", (req_id,)).fetchone()
    if req is None:
        flash("Request not found.")
        return redirect(url_for("signup_requests"))
    if req["status"] == "Pending":
        flash("This request is still pending. Approve or reject it before deleting.")
        return redirect(url_for("signup_requests"))

    db.execute("DELETE FROM signup_requests WHERE id = ?", (req_id,))
    db.commit()
    log_audit("Signup request deleted", f"username={req['username']}, id={req_id}")
    flash("Signup request deleted.")
    return redirect(url_for("signup_requests"))


# ---------------------------------------------------------------------------
# Login / logout
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()

        if user and user["is_active"] and check_password_hash(user["password_hash"], password):
            session["logged_in"] = True
            session["username"] = user["username"]
            session["role"] = user["role"]
            session["full_name"] = user["full_name"]
            session["employee_id"] = user["employee_id"]
            session["photo_path"] = user["photo_path"]
            session["user_id"] = user["id"]
            log_audit("Login", f"user={user['username']}, role={user['role']}")
            return redirect(url_for("dashboard"))
        else:
            flash("Wrong username or password.")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    if session.get("logged_in"):
        log_audit("Logout", f"user={session.get('username')}")
    session.clear()
    return redirect(url_for("login"))


@app.route("/settings")
@login_required
def settings_index():
    return render_template("settings.html")


EMPLOYEE_SELF_STATUSES = ["Active", "On Leave", "Resigned"]


@app.route("/profile", methods=["GET", "POST"])
@login_required
def view_profile():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (session.get("username"),)).fetchone()
    if user is None:
        flash("Account not found.")
        return redirect(url_for("dashboard"))

    employee = None
    if user["employee_id"]:
        employee = db.execute("SELECT * FROM employees WHERE id = ?", (user["employee_id"],)).fetchone()

    dept_names = get_department_names(db)
    role_names = get_designation_names(db)

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        department = request.form.get("department", "").strip()
        role = request.form.get("role", "").strip()
        status = request.form.get("status", "").strip()
        experience_raw = request.form.get("experience_years", "").strip()

        if not full_name:
            flash("Name can't be empty.")
            return redirect(url_for("view_profile"))

        if len(full_name) > 32:
            flash("Full name must be 32 characters or fewer.")
            return redirect(url_for("view_profile"))

        if not FULL_NAME_RE.match(full_name):
            flash("Full name can only contain letters and spaces.")
            return redirect(url_for("view_profile"))

        if not username:
            flash("Username can't be empty.")
            return redirect(url_for("view_profile"))

        if len(username) > 32:
            flash("Username must be 32 characters or fewer.")
            return redirect(url_for("view_profile"))

        if username != user["username"]:
            taken = db.execute(
                "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE AND id != ?",
                (username, user["id"]),
            ).fetchone()
            if taken:
                flash(f'"{username}" is already taken — please choose another username.')
                return redirect(url_for("view_profile"))

        if phone and (not phone.isdigit() or len(phone) != 10):
            flash("Phone number must be exactly 10 digits.")
            return redirect(url_for("view_profile"))

        if employee is not None:
            if department not in dept_names or role not in role_names:
                flash("Please choose a valid department and designation from the list.")
                return redirect(url_for("view_profile"))
            if status not in EMPLOYEE_SELF_STATUSES:
                flash("Please choose a valid status.")
                return redirect(url_for("view_profile"))
            experience_years = employee["experience_years"]
            if experience_raw:
                try:
                    experience_years = float(experience_raw)
                except ValueError:
                    flash("Experience must be a number.")
                    return redirect(url_for("view_profile"))
            else:
                experience_years = None

        old_username = user["username"]
        db.execute(
            "UPDATE users SET username = ?, full_name = ?, email = ? WHERE id = ?",
            (username, full_name, email, user["id"]),
        )

        # Keep the linked employee record's name/email/phone (and, since the person is
        # editing their own profile, department/designation/experience/status too — salary
        # and hire date stay Admin/HR-only) in step with what they enter here.
        if employee is not None:
            db.execute(
                "UPDATE employees SET name = ?, email = ?, phone = ?, department = ?, role = ?, "
                "status = ?, experience_years = ? WHERE id = ?",
                (full_name, email, phone, department, role, status, experience_years, employee["id"]),
            )

        session["full_name"] = full_name
        session["username"] = username
        db.commit()
        log_audit(
            "Profile updated",
            f"user={old_username}" + (f" (renamed to {username})" if username != old_username else ""),
        )
        flash("Profile updated.")
        return redirect(url_for("view_profile"))

    return render_template(
        "view_profile.html",
        user=user,
        employee=employee,
        departments=dept_names,
        roles=role_names,
        statuses=EMPLOYEE_SELF_STATUSES,
    )


@app.route("/settings/theme")
@login_required
def app_theme():
    return render_template("app_theme.html")


@app.route("/privacy", methods=["GET", "POST"])
@login_required
def privacy():
    db = get_db()

    if request.method == "POST":
        redirect_target = "view_profile" if request.form.get("next") == "view_profile" else "privacy"

        if request.form.get("remove_photo"):
            user = db.execute(
                "SELECT photo_path FROM users WHERE username = ?", (session.get("username"),)
            ).fetchone()
            if user and user["photo_path"]:
                disk_path = os.path.join("static", user["photo_path"])
                if os.path.exists(disk_path):
                    os.remove(disk_path)
                db.execute(
                    "UPDATE users SET photo_path = NULL WHERE username = ?",
                    (session.get("username"),),
                )
                db.commit()
                session["photo_path"] = None
                log_audit("Profile photo removed", f"user={session.get('username')}")
                flash("Profile photo removed.")
            else:
                flash("No profile photo to remove.")
            return redirect(url_for(redirect_target))

        photo_add = request.files.get("photo_add")
        photo_click = request.files.get("photo_click")
        photo = photo_add if (photo_add and photo_add.filename) else photo_click
        if photo and photo.filename:
            ext = photo.filename.rsplit(".", 1)[-1].lower() if "." in photo.filename else ""
            if ext not in ALLOWED_PHOTO_EXTENSIONS:
                flash("Please upload a photo in PNG, JPG, GIF, or WEBP format.")
                return redirect(url_for(redirect_target))

            os.makedirs(PROFILE_PHOTO_DIR, exist_ok=True)
            filename = secure_filename(f"user_{session.get('username')}.{ext}")
            disk_path = os.path.join(PROFILE_PHOTO_DIR, filename)
            photo.save(disk_path)

            relative_path = "/".join(["uploads", "profile_photos", filename])
            db.execute(
                "UPDATE users SET photo_path = ? WHERE username = ?",
                (relative_path, session.get("username")),
            )
            db.commit()
            session["photo_path"] = relative_path
            log_audit("Profile photo updated", f"user={session.get('username')}")
            flash("Profile photo updated.")
        else:
            flash("No photo was selected.")
        return redirect(url_for(redirect_target))

    return render_template("privacy.html")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (session.get("username"),)).fetchone()

        if user is None or not check_password_hash(user["password_hash"], current_password):
            flash("Current password is incorrect.")
            return render_template("change_password.html")

        if len(new_password) < 4:
            flash("New password must be at least 4 characters long.")
            return render_template("change_password.html")

        if new_password != confirm_password:
            flash("New password and confirm password don't match.")
            return render_template("change_password.html")

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user["id"]),
        )
        db.commit()
        log_audit("Password changed", f"user={user['username']}")
        flash("Your password has been changed successfully.")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()

        if (
            user is None
            or not user["email"]
            or user["email"].strip().lower() != email.lower()
        ):
            flash("We couldn't verify that username and email combination.")
            return render_template("forgot_password.html", username=username)

        if len(new_password) < 4:
            flash("New password must be at least 4 characters long.")
            return render_template("forgot_password.html", username=username)

        if new_password != confirm_password:
            flash("New password and confirm password don't match.")
            return render_template("forgot_password.html", username=username)

        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user["id"]),
        )
        db.commit()
        log_audit("Password reset via forgot password", f"user={user['username']}")
        flash("Password reset successful. Please sign in with your new password.")
        return redirect(url_for("login"))

    return render_template("forgot_password.html", username="")


init_db()

if __name__ == "__main__":
    app.run(debug=True)