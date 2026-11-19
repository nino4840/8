const express = require('express'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const app = express();
app.use(express.json({ limit: '14mb' }));
app.use((q, r, n) => { r.set('X-Frame-Options', 'DENY'); r.set('X-Content-Type-Options', 'nosniff'); n(); });

// ---------- ฐานข้อมูล (ไฟล์ JSON) ----------
const D = path.join(__dirname, 'data'); fs.mkdirSync(D + '/uploads', { recursive: true });
const F = D + '/db.json';
let db = fs.existsSync(F) ? JSON.parse(fs.readFileSync(F, 'utf8')) : { users: [], exams: [], attempts: [], logs: [] };
const save = () => { fs.writeFileSync(F + '.tmp', JSON.stringify(db)); fs.renameSync(F + '.tmp', F); };
const id = () => crypto.randomBytes(8).toString('hex');
const hash = (p, s = crypto.randomBytes(8).toString('hex')) => s + ':' + crypto.scryptSync(p, s, 32).toString('hex');
const check = (p, h) => { const a = Buffer.from(hash(p, h.split(':')[0])), b = Buffer.from(h); return a.length === b.length && crypto.timingSafeEqual(a, b); };
if (!db.users.some(u => u.role === 'admin')) {
  db.users.push({ id: id(), username: process.env.ADMIN_USER || 'admin', name: 'ผู้ดูแลระบบ', role: 'admin', pw: hash(process.env.ADMIN_PASS || 'admin1234') });
  save(); console.log('สร้างผู้ดูแลเริ่มต้นแล้ว: admin / admin1234 (กรุณาเปลี่ยนรหัสผ่านด้วย ADMIN_PASS)');
}

// ---------- Auth ----------
const sess = new Map();
const login = u => { const t = crypto.randomBytes(24).toString('hex'); sess.set(t, { uid: u.id, exp: Date.now() + 12 * 3600e3 }); return t; };
const pub = u => ({ id: u.id, username: u.username, name: u.name, role: u.role });
const auth = role => (req, res, next) => {
  const t = req.headers['x-token'] || req.query.token, s = sess.get(t);
  const u = s && s.exp > Date.now() && db.users.find(x => x.id === s.uid);
  if (!u) return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบ' });
  if (role && u.role !== role) return res.status(403).json({ error: 'ไม่มีสิทธิ์' });
  req.user = u; next();
};
const wrap = f => (req, res) => { try { f(req, res); } catch (e) { res.status(400).json({ error: e.message }); } };

app.post('/api/register', wrap((req, res) => {
  if (process.env.ALLOW_REGISTER === '0') throw new Error('ปิดรับสมัครเอง กรุณาติดต่อผู้ดูแล');
  const { username, password, name } = req.body;
  if (!username || !password || password.length < 6) throw new Error('ต้องมีชื่อผู้ใช้และรหัสผ่านอย่างน้อย 6 ตัว');
  if (db.users.some(u => u.username === username)) throw new Error('ชื่อผู้ใช้นี้ถูกใช้แล้ว');
  const u = { id: id(), username: String(username).slice(0, 50), name: String(name || username).slice(0, 100), role: 'student', pw: hash(String(password)) };
  db.users.push(u); save(); res.json({ token: login(u), user: pub(u) });
}));
app.post('/api/login', wrap((req, res) => {
  const u = db.users.find(x => x.username === req.body.username);
  if (!u || !check(String(req.body.password || ''), u.pw)) throw new Error('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
  res.json({ token: login(u), user: pub(u) });
}));
app.get('/api/me', auth(), (req, res) => res.json({ user: pub(req.user) }));

// ---------- ตรวจข้อสอบ ----------
const log = (a, type) => db.logs.push({ id: id(), attemptId: a.id, t: Date.now(), type });
const total = ex => ex.questions.reduce((s, q) => s + q.points, 0);
const sum = o => Object.values(o || {}).reduce((s, x) => s + (+x || 0), 0);
const score = a => sum(a.auto) + sum(a.manual);
const pending = (a, ex) => ex.questions.some(q => (q.type === 'essay' || q.type === 'file') && a.manual[q.id] == null);
function grade(ex, ans) {
  const auto = {};
  for (const q of ex.questions) {
    const a = ans[q.id]; let p;
    if (q.type === 'mcq') p = a != null && String(a) === String(q.answer) ? q.points : 0;
    else if (q.type === 'short') p = a && String(q.answer).split('|').some(x => x.trim().toLowerCase() === String(a).trim().toLowerCase()) ? q.points : 0;
    else continue;
    auto[q.id] = p;
  }
  return auto;
}
function finalize(a, reason) {
  if (a.status !== 'in_progress') return;
  const ex = db.exams.find(e => e.id === a.examId);
  a.status = 'submitted'; a.submittedAt = Date.now(); a.reason = reason; a.auto = grade(ex, a.answers);
  log(a, 'submit:' + reason); save();
}
setInterval(() => { const n = Date.now(); db.attempts.forEach(a => { if (a.status === 'in_progress' && n > a.deadline + 5000) finalize(a, 'timeout'); }); }, 10000);

const strip = q => ({ id: q.id, type: q.type, text: q.text, options: q.options, points: q.points });
const resultOf = (a, ex) => a.status === 'submitted' && ex.showResult ? { score: score(a), total: total(ex), pending: pending(a, ex) } : null;
const attView = (a, ex) => ({ id: a.id, status: a.status, deadline: a.deadline, serverNow: Date.now(), answers: a.answers,
  exam: { title: ex.title, questions: ex.questions.map(strip) }, result: resultOf(a, ex) });

// ---------- ฝั่งผู้สอบ ----------
app.get('/api/exams', auth('student'), (req, res) => {
  const now = Date.now();
  const list = db.exams.filter(e => e.closeAt > now - 30 * 864e5).map(e => {
    const a = db.attempts.find(x => x.examId === e.id && x.userId === req.user.id);
    if (a && a.status === 'in_progress' && now > a.deadline + 5000) finalize(a, 'timeout');
    return { id: e.id, title: e.title, duration: e.duration, openAt: e.openAt, closeAt: e.closeAt, status: a ? a.status : 'new', result: a ? resultOf(a, e) : null };
  });
  res.json({ exams: list });
});
app.post('/api/exams/:id/start', auth('student'), wrap((req, res) => {
  const ex = db.exams.find(e => e.id === req.params.id); if (!ex) throw new Error('ไม่พบข้อสอบ');
  const now = Date.now(); let a = db.attempts.find(x => x.examId === ex.id && x.userId === req.user.id);
  if (!a) {
    if (now < ex.openAt) throw new Error('ยังไม่ถึงเวลาสอบ');
    if (now > ex.closeAt) throw new Error('หมดเวลาสอบแล้ว');
    a = { id: id(), examId: ex.id, userId: req.user.id, startedAt: now, deadline: Math.min(now + ex.duration * 60000, ex.closeAt),
      status: 'in_progress', answers: {}, violations: 0, lastSeen: now, manual: {} };
    db.attempts.push(a); log(a, 'start');
  } else if (a.status === 'in_progress') log(a, 'resume');
  if (a.status === 'in_progress' && now > a.deadline + 5000) finalize(a, 'timeout');
  save(); res.json(attView(a, ex));
}));
function mine(req) {
  const a = db.attempts.find(x => x.id === req.params.id && x.userId === req.user.id); if (!a) throw new Error('ไม่พบข้อมูล');
  const ex = db.exams.find(e => e.id === a.examId);
  if (a.status === 'in_progress' && Date.now() > a.deadline + 5000) finalize(a, 'timeout');
  return { a, ex };
}
function merge(a, ex, ans) {
  if (!ans || typeof ans !== 'object') return;
  for (const q of ex.questions) if (q.type !== 'file' && q.id in ans) a.answers[q.id] = String(ans[q.id]).slice(0, 20000);
}
app.get('/api/attempts/:id', auth('student'), wrap((req, res) => { const { a, ex } = mine(req); res.json(attView(a, ex)); }));
app.put('/api/attempts/:id/answers', auth('student'), wrap((req, res) => {
  const { a, ex } = mine(req);
  if (a.status !== 'in_progress') return res.status(409).json({ error: 'ส่งข้อสอบแล้ว แก้ไขไม่ได้', status: a.status });
  merge(a, ex, req.body.answers); a.lastSeen = Date.now(); save(); res.json({ ok: true, serverNow: Date.now() });
}));
app.post('/api/attempts/:id/event', auth('student'), wrap((req, res) => {
  const { a, ex } = mine(req);
  if (a.status !== 'in_progress') return res.json({ status: a.status });
  const type = String(req.body.type || '').slice(0, 30), counted = ['blur', 'hidden', 'fs_exit'].includes(type);
  log(a, type); a.lastSeen = Date.now();
  if (counted) a.violations++;
  if (counted && ex.maxViolations > 0 && a.violations >= ex.maxViolations) finalize(a, 'violation');
  save(); res.json({ status: a.status, counted, violations: a.violations, max: ex.maxViolations });
}));
app.post('/api/attempts/:id/upload', auth('student'), wrap((req, res) => {
  const { a, ex } = mine(req);
  if (a.status !== 'in_progress') throw new Error('ส่งข้อสอบแล้ว แก้ไขไม่ได้');
  const q = ex.questions.find(x => x.id === req.body.qid && x.type === 'file'); if (!q) throw new Error('ข้อนี้ไม่รับไฟล์');
  const buf = Buffer.from(String(req.body.data || ''), 'base64'); if (!buf.length || buf.length > 10 * 1024 * 1024) throw new Error('ไฟล์ต้องมีขนาดไม่เกิน 10MB');
  const fid = id(); fs.writeFileSync(path.join(D, 'uploads', fid), buf);
  a.answers[q.id] = { fid, name: String(req.body.name || 'file').slice(0, 120), size: buf.length };
  log(a, 'upload'); save(); res.json({ ok: true, name: a.answers[q.id].name });
}));
app.post('/api/attempts/:id/submit', auth('student'), wrap((req, res) => {
  const { a, ex } = mine(req);
  if (a.status === 'in_progress') { merge(a, ex, req.body.answers); finalize(a, 'manual'); }
  res.json(attView(a, ex));
}));

// ---------- ฝั่งผู้ดูแล ----------
function clean(b) {
  const n = (x, d) => Number.isFinite(+x) && x !== '' && x != null ? +x : d;
  if (!b.title || !Array.isArray(b.questions) || !b.questions.length) throw new Error('กรุณากรอกชื่อข้อสอบและเพิ่มอย่างน้อย 1 ข้อ');
  const e = { title: String(b.title).slice(0, 200), duration: Math.max(1, n(b.duration, 60)), openAt: n(b.openAt, Date.now()), closeAt: n(b.closeAt, Date.now() + 864e5),
    maxViolations: Math.max(0, n(b.maxViolations, 3)), showResult: !!b.showResult,
    questions: b.questions.map(q => {
      const t = ['mcq', 'short', 'essay', 'file'].includes(q.type) ? q.type : 'mcq';
      const o = { id: q.id || id(), type: t, text: String(q.text || '').slice(0, 5000), points: Math.max(0, n(q.points, 1)), answer: q.answer == null ? '' : String(q.answer) };
      if (t === 'mcq') { o.options = (q.options || []).map(String); if (o.options.length < 2) throw new Error('ข้อปรนัยต้องมีอย่างน้อย 2 ตัวเลือก'); if (!(+o.answer >= 1 && +o.answer <= o.options.length)) throw new Error('ข้อปรนัยต้องระบุข้อที่ถูก (เลขลำดับตัวเลือก)'); }
      if (t === 'short' && !o.answer.trim()) throw new Error('ข้อคำตอบสั้นต้องมีเฉลย');
      return o;
    }) };
  if (e.closeAt <= e.openAt) throw new Error('เวลาปิดต้องหลังเวลาเปิด');
  return e;
}
app.get('/api/admin/exams', auth('admin'), (req, res) => res.json({ exams: db.exams.map(e => ({ id: e.id, title: e.title, duration: e.duration, openAt: e.openAt, closeAt: e.closeAt,
  questions: e.questions.length, attempts: db.attempts.filter(a => a.examId === e.id).length })) }));
app.get('/api/admin/exams/:id', auth('admin'), wrap((req, res) => { const e = db.exams.find(x => x.id === req.params.id); if (!e) throw new Error('ไม่พบ'); res.json(e); }));
app.post('/api/admin/exams', auth('admin'), wrap((req, res) => { const e = { id: id(), ...clean(req.body) }; db.exams.push(e); save(); res.json(e); }));
app.put('/api/admin/exams/:id', auth('admin'), wrap((req, res) => {
  const i = db.exams.findIndex(x => x.id === req.params.id); if (i < 0) throw new Error('ไม่พบ');
  if (db.attempts.some(a => a.examId === req.params.id)) throw new Error('มีผู้เริ่มสอบแล้ว แก้ไขข้อสอบไม่ได้');
  db.exams[i] = { id: req.params.id, ...clean(req.body) }; save(); res.json(db.exams[i]);
}));
app.delete('/api/admin/exams/:id', auth('admin'), wrap((req, res) => {
  const ids = db.attempts.filter(a => a.examId === req.params.id).map(a => a.id);
  db.exams = db.exams.filter(e => e.id !== req.params.id); db.attempts = db.attempts.filter(a => !ids.includes(a.id)); db.logs = db.logs.filter(l => !ids.includes(l.attemptId)); save(); res.json({ ok: true });
}));
const uname = uid => (db.users.find(u => u.id === uid) || {}).name || '?';
app.get('/api/admin/exams/:id/attempts', auth('admin'), wrap((req, res) => {
  const ex = db.exams.find(e => e.id === req.params.id); if (!ex) throw new Error('ไม่พบ');
  const now = Date.now();
  const rows = db.attempts.filter(a => a.examId === ex.id).map(a => {
    if (a.status === 'in_progress' && now > a.deadline + 5000) finalize(a, 'timeout');
    const u = db.users.find(x => x.id === a.userId) || {};
    return { id: a.id, name: u.name, username: u.username, status: a.status, reason: a.reason, answered: Object.keys(a.answers).length, violations: a.violations,
      lastSeen: a.lastSeen, startedAt: a.startedAt, deadline: a.deadline, score: a.status === 'submitted' ? score(a) : null, pending: a.status === 'submitted' && pending(a, ex) };
  });
  res.json({ exam: { id: ex.id, title: ex.title, total: total(ex), questions: ex.questions.length }, rows, serverNow: now });
}));
app.get('/api/admin/attempts/:id', auth('admin'), wrap((req, res) => {
  const a = db.attempts.find(x => x.id === req.params.id); if (!a) throw new Error('ไม่พบ');
  const ex = db.exams.find(e => e.id === a.examId);
  res.json({ attempt: a, exam: ex, student: uname(a.userId), total: total(ex), score: score(a), logs: db.logs.filter(l => l.attemptId === a.id).sort((x, y) => x.t - y.t) });
}));
app.post('/api/admin/attempts/:id/grade', auth('admin'), wrap((req, res) => {
  const a = db.attempts.find(x => x.id === req.params.id); if (!a) throw new Error('ไม่พบ');
  if (a.status !== 'submitted') throw new Error('ผู้สอบยังไม่ส่งข้อสอบ');
  const ex = db.exams.find(e => e.id === a.examId);
  for (const q of ex.questions) if ((q.type === 'essay' || q.type === 'file') && req.body.manual && req.body.manual[q.id] !== '' && req.body.manual[q.id] != null)
    a.manual[q.id] = Math.min(q.points, Math.max(0, +req.body.manual[q.id] || 0));
  log(a, 'graded_by_admin'); save(); res.json({ score: score(a), total: total(ex) });
}));
app.get('/api/admin/files/:fid', auth('admin'), wrap((req, res) => {
  const fid = req.params.fid.replace(/[^a-f0-9]/g, ''); const f = path.join(D, 'uploads', fid); if (!fs.existsSync(f)) throw new Error('ไม่พบไฟล์');
  let name = fid; for (const a of db.attempts) for (const v of Object.values(a.answers)) if (v && v.fid === fid) name = v.name;
  res.set('Content-Disposition', "attachment; filename*=UTF-8''" + encodeURIComponent(name)); res.sendFile(f);
}));
const cell = v => { v = String(v ?? ''); if (/^[=+\-@]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; };
app.get('/api/admin/exams/:id/export.csv', auth('admin'), wrap((req, res) => {
  const ex = db.exams.find(e => e.id === req.params.id); if (!ex) throw new Error('ไม่พบ');
  const rows = [['username', 'ชื่อ', 'สถานะ', 'คะแนน', 'เต็ม', 'ครั้งที่ละเมิด', 'เวลาเริ่ม', 'เวลาส่ง', 'สาเหตุการส่ง', 'รอตรวจ']];
  db.attempts.filter(a => a.examId === ex.id).forEach(a => { const u = db.users.find(x => x.id === a.userId) || {};
    rows.push([u.username, u.name, a.status, a.status === 'submitted' ? score(a) : '', total(ex), a.violations, new Date(a.startedAt).toLocaleString('th-TH'),
      a.submittedAt ? new Date(a.submittedAt).toLocaleString('th-TH') : '', a.reason || '', a.status === 'submitted' && pending(a, ex) ? 'ใช่' : '']); });
  res.set('Content-Type', 'text/csv; charset=utf-8'); res.set('Content-Disposition', 'attachment; filename="results.csv"');
  res.send('\ufeff' + rows.map(r => r.map(cell).join(',')).join('\r\n'));
}));
app.get('/api/admin/users', auth('admin'), (req, res) => res.json({ users: db.users.filter(u => u.role === 'student').map(pub) }));
app.post('/api/admin/users', auth('admin'), wrap((req, res) => {
  let added = 0;
  for (const r of req.body.list || []) {
    if (!r.username || !r.password || String(r.password).length < 6 || db.users.some(u => u.username === r.username)) continue;
    db.users.push({ id: id(), username: String(r.username).slice(0, 50), name: String(r.name || r.username).slice(0, 100), role: 'student', pw: hash(String(r.password)) }); added++;
  }
  save(); res.json({ added });
}));

app.use(express.static(path.join(__dirname, 'public')));
const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => console.log('ระบบสอบออนไลน์ทำงานที่ http://localhost:' + port));
