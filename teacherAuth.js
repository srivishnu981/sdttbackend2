// backend/teacherAuth.js
// Teacher accounts (teacher code + password), session history and live attendance.
// Install once:  npm install bcryptjs jsonwebtoken
//
// Assumes you already use better-sqlite3 (`db`) and Express (`app`) in server.js.

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.TEACHER_JWT_SECRET || 'change-this-secret-before-demo';

// Same roster as teacherData.ts on the app side. Only these codes can create an account.
const TEACHERS = {
  T101: 'Prof. Sharma',
  T102: 'Prof. Rao',
  T103: 'Dr. Sunil P V',
};

// ---------- tables ----------
function initTeacherTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS teachers (
      teacher_code  TEXT PRIMARY KEY,
      name          TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at    TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      teacher_code TEXT NOT NULL,
      class_id     TEXT NOT NULL,
      class_name   TEXT,
      started_at   TEXT NOT NULL DEFAULT (datetime('now')),
      ended_at     TEXT
    );

    CREATE TABLE IF NOT EXISTS attendance_records (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id INTEGER NOT NULL,
      roll_no    TEXT NOT NULL,
      name       TEXT,
      marked_at  TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(session_id, roll_no)
    );
  `);
}

// ---------- helpers you call from your existing session / attendance endpoints ----------
function logSessionStart(db, teacherCode, classId, className) {
  const r = db
    .prepare('INSERT INTO sessions (teacher_code, class_id, class_name) VALUES (?, ?, ?)')
    .run(teacherCode, classId, className || classId);
  return r.lastInsertRowid; // keep this as your session's dbSessionId
}

function logSessionEnd(db, sessionId) {
  db.prepare("UPDATE sessions SET ended_at = datetime('now') WHERE id = ? AND ended_at IS NULL").run(sessionId);
}

function logAttendance(db, sessionId, rollNo, name) {
  // UNIQUE(session_id, roll_no) + INSERT OR IGNORE = a student can't be counted twice
  db.prepare('INSERT OR IGNORE INTO attendance_records (session_id, roll_no, name) VALUES (?, ?, ?)').run(
    sessionId,
    rollNo,
    name || null
  );
}

// ---------- auth middleware ----------
function requireTeacher(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'teacher') throw new Error('wrong role');
    req.teacher = { code: payload.code, name: payload.name };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Session expired, please log in again' });
  }
}

function signToken(code, name) {
  return jwt.sign({ role: 'teacher', code, name }, JWT_SECRET, { expiresIn: '30d' });
}

// ---------- router ----------
function createTeacherRouter(db) {
  initTeacherTables(db);
  const router = express.Router();

  // Create account: only a teacher code from the roster, plus a password the teacher picks.
  router.post('/register', (req, res) => {
    const code = String(req.body.teacherCode || '').trim().toUpperCase();
    const password = String(req.body.password || '');

    if (!TEACHERS[code]) return res.status(400).json({ error: 'Invalid teacher code' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existing = db.prepare('SELECT 1 FROM teachers WHERE teacher_code = ?').get(code);
    if (existing) return res.status(409).json({ error: 'Account already exists. Please log in.' });

    const hash = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO teachers (teacher_code, name, password_hash) VALUES (?, ?, ?)').run(code, TEACHERS[code], hash);

    res.json({ token: signToken(code, TEACHERS[code]), teacher: { code, name: TEACHERS[code] } });
  });

  // Login with teacher code + password
  router.post('/login', (req, res) => {
    const code = String(req.body.teacherCode || '').trim().toUpperCase();
    const password = String(req.body.password || '');

    const row = db.prepare('SELECT * FROM teachers WHERE teacher_code = ?').get(code);
    if (!row) {
      // Tell the app whether the code is valid but has no account yet, so it can switch to "create account"
      return res.status(404).json({ error: TEACHERS[code] ? 'No account yet. Create one first.' : 'Invalid teacher code', needsRegister: !!TEACHERS[code] });
    }
    if (!bcrypt.compareSync(password, row.password_hash)) {
      return res.status(401).json({ error: 'Wrong password' });
    }
    res.json({ token: signToken(row.teacher_code, row.name), teacher: { code: row.teacher_code, name: row.name } });
  });

  router.post('/change-password', requireTeacher, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const row = db.prepare('SELECT * FROM teachers WHERE teacher_code = ?').get(req.teacher.code);
    if (!row || !bcrypt.compareSync(String(oldPassword || ''), row.password_hash)) {
      return res.status(401).json({ error: 'Old password is wrong' });
    }
    if (String(newPassword || '').length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    db.prepare('UPDATE teachers SET password_hash = ? WHERE teacher_code = ?').run(bcrypt.hashSync(newPassword, 10), req.teacher.code);
    res.json({ ok: true });
  });

  // LIVE: the teacher's currently running session + who has marked so far (can be called any time)
  router.get('/live', requireTeacher, (req, res) => {
    const session = db
      .prepare('SELECT * FROM sessions WHERE teacher_code = ? AND ended_at IS NULL ORDER BY id DESC LIMIT 1')
      .get(req.teacher.code);
    if (!session) return res.json({ active: false });

    const records = db
      .prepare('SELECT roll_no, name, marked_at FROM attendance_records WHERE session_id = ? ORDER BY marked_at DESC')
      .all(session.id);
    res.json({ active: true, session, count: records.length, records });
  });

  // HISTORY: all this teacher's sessions (newest first) with present counts
  router.get('/sessions', requireTeacher, (req, res) => {
    const sessions = db
      .prepare(
        `SELECT s.*, (SELECT COUNT(*) FROM attendance_records a WHERE a.session_id = s.id) AS present_count
         FROM sessions s WHERE s.teacher_code = ? ORDER BY s.id DESC LIMIT 100`
      )
      .all(req.teacher.code);
    res.json({ sessions });
  });

  // One past (or current) session's full attendance list
  router.get('/sessions/:id', requireTeacher, (req, res) => {
    const session = db.prepare('SELECT * FROM sessions WHERE id = ? AND teacher_code = ?').get(req.params.id, req.teacher.code);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    const records = db
      .prepare('SELECT roll_no, name, marked_at FROM attendance_records WHERE session_id = ? ORDER BY roll_no')
      .all(session.id);
    res.json({ session, count: records.length, records });
  });

  return router;
}

   module.exports = { createTeacherRouter, requireTeacher, logSessionStart, logSessionEnd, logAttendance, TEACHERS };
/* ============ WIRING IN server.js ============

const { createTeacherRouter, logSessionStart, logSessionEnd, logAttendance } = require('./teacherAuth');
app.use(express.json());                      // if not already there
app.use('/teacher', createTeacherRouter(db)); // db = your better-sqlite3 instance

// 1) in /session/start (after you know teacherCode + class):
//      const dbSessionId = logSessionStart(db, teacherCode, classId, className);
//      currentSession.dbSessionId = dbSessionId;      // store next to your in-memory session

// 2) in /attendance/mark (right after the token is validated and the student is accepted):
//      logAttendance(db, currentSession.dbSessionId, student.roll_no, student.name);

// 3) in /session/end:
//      logSessionEnd(db, currentSession.dbSessionId);

If /session/start doesn't currently receive teacherCode, send it from the app in the request body
(the teacher is logged in, so the app knows it).
=============================================== */