CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS designations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    department TEXT   -- which department this designation belongs to (matches departments.name);
                       -- NULL means it's available under every department
);

CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_no TEXT UNIQUE,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT,
    department TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Active',
    salary REAL,
    experience_years REAL,
    join_date TEXT NOT NULL,
    paid_leaves_override INTEGER,
    unpaid_leaves_override INTEGER,
    total_leaves_override INTEGER
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'Employee',   -- Admin | HR Manager | Employee
    employee_id INTEGER,                     -- linked employee record, if role = Employee
    email TEXT,                              -- used to verify identity for "forgot password"
    is_active INTEGER NOT NULL DEFAULT 1,
    photo_path TEXT,                         -- profile photo, relative to /static
    FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Present',
    check_in TEXT,
    check_out TEXT,
    UNIQUE(employee_id, date),
    FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS leaves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    leave_type TEXT NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    reason TEXT,
    status TEXT NOT NULL DEFAULT 'Pending',   -- Pending | Approved | Rejected
    applied_on TEXT NOT NULL,
    decided_by TEXT,
    decided_on TEXT,
    FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    username TEXT NOT NULL,
    role TEXT,
    action TEXT NOT NULL,
    details TEXT
);

CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    posted_by TEXT NOT NULL,
    posted_by_role TEXT,
    created_at TEXT NOT NULL,
    updated_by TEXT,
    updated_at TEXT
);

CREATE TABLE IF NOT EXISTS report_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    notes TEXT,
    updated_by TEXT,
    updated_at TEXT
);

-- Tracks which announcements each user has already seen, so the navbar badge
-- only counts announcements that particular user hasn't opened the list for yet.
CREATE TABLE IF NOT EXISTS announcement_reads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    announcement_id INTEGER NOT NULL,
    read_at TEXT NOT NULL,
    UNIQUE(user_id, announcement_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (announcement_id) REFERENCES announcements(id) ON DELETE CASCADE
);

-- Self-signup requests submitted from the public "Create Account" page.
-- An Admin reviews each request; approving one creates the employee record
-- and the login account, rejecting one leaves no account behind.
CREATE TABLE IF NOT EXISTS signup_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT,
    department TEXT NOT NULL,
    role TEXT NOT NULL,
    experience_years REAL,
    hire_date TEXT,
    status TEXT NOT NULL DEFAULT 'Pending',   -- Pending | Approved | Rejected
    requested_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    employee_id INTEGER
);
