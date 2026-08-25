# Employee Management System — Role-Based Edition

A Flask portal covering: employee management, department & designation
management, login with role-based access control, attendance, leave management,
dashboards, reports, and audit logs.

## Run it locally

    pip install -r requirements.txt
    python app.py

Then open http://127.0.0.1:5000 — with no `DATABASE_URL` set, the app uses a
local SQLite file (`database.db`), created automatically on first run, so you
can develop without installing Postgres.

## Deploying on Render (persistent database)

Render's filesystem is **ephemeral** — any file a running service writes to
disk (including a local SQLite `database.db`) gets wiped on every redeploy,
restart, or scale-to-zero. That's what was causing data to "randomly change
or disappear" in production. The fix is to use a real, persistent database
instead of a file on disk:

1. In the Render dashboard, create a **PostgreSQL** instance (the free tier
   is fine to start).
2. Copy its **Internal Database URL**.
3. On your web service, add an environment variable `DATABASE_URL` set to
   that value, plus a `SECRET_KEY` (any random string) for session security.
4. Set the service's **Start Command** to `gunicorn app:app` (a `Procfile`
   with this is already included).
5. Deploy. On first boot the app automatically creates all tables and seed
   data in Postgres — no manual migration step needed.

From then on, your data lives in Postgres and survives redeploys/restarts
just like it would on any other host.

`db_compat.py` is what makes this work with almost no changes to the rest of
the code: when `DATABASE_URL` is set it talks to Postgres (translating the
handful of SQLite-only bits — `?` placeholders, `COLLATE NOCASE`, `PRAGMA
table_info`, `cur.lastrowid`); when it isn't set, it falls back to plain
SQLite for local dev.

## Default logins (change these after first login in a real deployment)

| Username     | Password       | Role        |
|--------------|----------------|-------------|
| Subham       | Thakur         | Admin       |
| hr.manager   | HrManager@123  | HR Manager  |
| employee     | Employee@123   | Employee (linked to the seeded "Ananya Sharma" record) |


## Roles & access

- **Admin** — full access to every module, including audit logs.
- **HR Manager** — manage employees, departments, designations, attendance,
  approve/reject leave requests, view reports. No audit log access.
- **Employee** — view own profile, mark/view own attendance, apply for and
  track their own leave requests.

## Modules

- **Employees** — add/edit/delete/search, filter by department.
- **Departments** — CRUD, headcount and salary rollups per department.
- **Designations** — CRUD, headcount per designation (replaces the old
  fixed "Role" dropdown with a manageable table).
- **Login & RBAC** — `users` table with hashed passwords (werkzeug), three
  roles enforced via a `roles_required()` decorator on every route.
- **Attendance** — daily roster marking (staff) / personal view (employee).
- **Leave management** — apply, list, approve/reject, auto-reflects an
  approved leave that covers today as "On Leave" on the employee record.
- **Dashboards** — role-aware: staff see org-wide stats + pending leave
  and today's attendance coverage; employees see their own attendance and
  leave history.
- **Reports** — department strength, status breakdown, leave summary by
  status/type, monthly attendance per employee, total payroll.
- **Audit logs** — every login/logout, and every add/edit/delete across
  employees, departments, designations, attendance, and leave decisions is
  recorded with timestamp, user, role, action, and details (Admin only).

## Notes

- No real assignment/spec document was attached to this task — the schema
  above was built directly from the module list given in the request
  (employee management, department & designation management, login &
  RBAC, attendance, leave management, dashboards, reports, audit logs).
  If you have a formal requirements document, share it and the module
  details (field names, workflow rules, report formats) can be tightened
  to match it exactly.
