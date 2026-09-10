// ---------------------------------------------------------------------------
// Квант Майнинг ХХК — Засварын сарын планер (нэвтрэлттэй веб апп)
// Express сервер: нэвтрэлт (JWT + bcrypt), эрхийн зэрэглэл, tasks/users API
// ---------------------------------------------------------------------------
require("dotenv").config();
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { pool, init } = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const IS_PROD = process.env.NODE_ENV === "production";

app.use(express.json({ limit: "256kb" }));
app.use(cookieParser());

// ----------------------------- Туслах функцууд -----------------------------
function signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}
function setAuthCookie(res, token) {
  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}
function requireAuth(req, res, next) {
  const token = req.cookies && req.cookies.token;
  if (!token) return res.status(401).json({ error: "Нэвтрээгүй байна" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: "Нэвтрэлт хүчингүй боллоо" });
  }
}
function requireRole(roles) {
  return function (req, res, next) {
    if (!req.user || roles.indexOf(req.user.role) < 0) {
      return res.status(403).json({ error: "Танд энэ үйлдлийг хийх эрх алга" });
    }
    next();
  };
}
function newId() {
  return "t" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}
function mapTask(r) {
  return {
    id: r.id,
    machine: r.machine,
    unit: r.unit,
    work: r.work,
    team: r.team,
    lead: r.lead,
    parts: r.parts,
    start: r.start_date,
    end: r.end_date,
    status: r.status,
  };
}
const STATUSES = ["plan", "wait", "prog", "done", "delay"];
const ROLES = ["admin", "editor", "viewer"];

// --------------------------------- Нэвтрэлт ---------------------------------
app.post("/api/login", async (req, res) => {
  const username = String((req.body.username || "")).trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!username || !password)
    return res.status(400).json({ error: "Нэр болон нууц үгээ оруулна уу" });
  try {
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: "Нэр эсвэл нууц үг буруу байна" });
    setAuthCookie(res, signToken(user));
    res.json({ user: { username: user.username, name: user.name, role: user.role } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ ok: true });
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    user: {
      username: req.user.username,
      name: req.user.name,
      role: req.user.role,
    },
  });
});

app.post("/api/password", requireAuth, async (req, res) => {
  const current = String(req.body.current || "");
  const next = String(req.body.next || "");
  if (next.length < 6)
    return res.status(400).json({ error: "Шинэ нууц үг доод тал нь 6 тэмдэгт байх ёстой" });
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
    const user = rows[0];
    if (!user || !(await bcrypt.compare(current, user.password)))
      return res.status(401).json({ error: "Одоогийн нууц үг буруу байна" });
    const hash = await bcrypt.hash(next, 10);
    await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, req.user.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

// ------------------------------- Ажлууд (tasks) -----------------------------
app.get("/api/tasks", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM tasks ORDER BY start_date ASC");
    res.json(rows.map(mapTask));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

function validTask(b) {
  if (!b || !String(b.machine || "").trim()) return "Машины нэр шаардлагатай";
  if (!String(b.work || "").trim()) return "Ажлын төрөл шаардлагатай";
  if (!String(b.start || "").match(/^\d{4}-\d{2}-\d{2}$/)) return "Эхлэх огноо буруу";
  if (!String(b.end || "").match(/^\d{4}-\d{2}-\d{2}$/)) return "Дуусах огноо буруу";
  if (b.end < b.start) return "Дуусах огноо эхлэхээс өмнө байж болохгүй";
  return null;
}

app.post("/api/tasks", requireAuth, requireRole(["admin", "editor"]), async (req, res) => {
  const b = req.body || {};
  const err = validTask(b);
  if (err) return res.status(400).json({ error: err });
  const id = newId();
  const status = STATUSES.indexOf(b.status) >= 0 ? b.status : "plan";
  try {
    await pool.query(
      `INSERT INTO tasks (id,machine,unit,work,team,lead,parts,start_date,end_date,status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [id, b.machine.trim(), (b.unit || "").trim(), b.work.trim(), (b.team || "").trim(),
       (b.lead || "").trim(), (b.parts || "").trim(), b.start, b.end, status]
    );
    const { rows } = await pool.query("SELECT * FROM tasks WHERE id=$1", [id]);
    res.json(mapTask(rows[0]));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

app.put("/api/tasks/:id", requireAuth, requireRole(["admin", "editor"]), async (req, res) => {
  const b = req.body || {};
  const err = validTask(b);
  if (err) return res.status(400).json({ error: err });
  const status = STATUSES.indexOf(b.status) >= 0 ? b.status : "plan";
  try {
    const r = await pool.query(
      `UPDATE tasks SET machine=$1,unit=$2,work=$3,team=$4,lead=$5,parts=$6,
        start_date=$7,end_date=$8,status=$9 WHERE id=$10`,
      [b.machine.trim(), (b.unit || "").trim(), b.work.trim(), (b.team || "").trim(),
       (b.lead || "").trim(), (b.parts || "").trim(), b.start, b.end, status, req.params.id]
    );
    if (!r.rowCount) return res.status(404).json({ error: "Ажил олдсонгүй" });
    const { rows } = await pool.query("SELECT * FROM tasks WHERE id=$1", [req.params.id]);
    res.json(mapTask(rows[0]));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

app.delete("/api/tasks/:id", requireAuth, requireRole(["admin", "editor"]), async (req, res) => {
  try {
    await pool.query("DELETE FROM tasks WHERE id=$1", [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

// ----------------------- Хэрэглэгч удирдах (зөвхөн админ) --------------------
app.get("/api/users", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT id,username,name,role,created_at FROM users ORDER BY id ASC"
    );
    res.json(rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

app.post("/api/users", requireAuth, requireRole(["admin"]), async (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const name = String(req.body.name || "").trim();
  const password = String(req.body.password || "");
  const role = ROLES.indexOf(req.body.role) >= 0 ? req.body.role : "viewer";
  if (!username.match(/^[a-z0-9._-]{3,32}$/))
    return res.status(400).json({ error: "Нэвтрэх нэр 3-32 тэмдэгт (латин үсэг, тоо) байх ёстой" });
  if (password.length < 6)
    return res.status(400).json({ error: "Нууц үг доод тал нь 6 тэмдэгт байх ёстой" });
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (username,name,password,role) VALUES ($1,$2,$3,$4)",
      [username, name, hash, role]
    );
    res.json({ ok: true });
  } catch (e) {
    if (e.code === "23505")
      return res.status(409).json({ error: "Энэ нэвтрэх нэр аль хэдийн бүртгэлтэй байна" });
    console.error(e);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

app.put("/api/users/:id", requireAuth, requireRole(["admin"]), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const role = ROLES.indexOf(req.body.role) >= 0 ? req.body.role : null;
  const password = req.body.password ? String(req.body.password) : null;
  try {
    if (role) {
      // Сүүлчийн админыг харагч болгохоос сэргийлэх
      if (role !== "admin") {
        const { rows } = await pool.query("SELECT COUNT(*)::int AS c FROM users WHERE role='admin'");
        const { rows: cur } = await pool.query("SELECT role FROM users WHERE id=$1", [id]);
        if (cur[0] && cur[0].role === "admin" && rows[0].c <= 1)
          return res.status(400).json({ error: "Хамгийн багадаа нэг админ үлдэх ёстой" });
      }
      await pool.query("UPDATE users SET role=$1 WHERE id=$2", [role, id]);
    }
    if (password) {
      if (password.length < 6)
        return res.status(400).json({ error: "Нууц үг доод тал нь 6 тэмдэгт байх ёстой" });
      const hash = await bcrypt.hash(password, 10);
      await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, id]);
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

app.delete("/api/users/:id", requireAuth, requireRole(["admin"]), async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (id === req.user.id)
    return res.status(400).json({ error: "Өөрийгөө устгах боломжгүй" });
  try {
    const { rows: cur } = await pool.query("SELECT role FROM users WHERE id=$1", [id]);
    if (cur[0] && cur[0].role === "admin") {
      const { rows } = await pool.query("SELECT COUNT(*)::int AS c FROM users WHERE role='admin'");
      if (rows[0].c <= 1)
        return res.status(400).json({ error: "Хамгийн багадаа нэг админ үлдэх ёстой" });
    }
    await pool.query("DELETE FROM users WHERE id=$1", [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Серверийн алдаа" });
  }
});

// -------------------------------- Хуудсууд ----------------------------------
app.use(express.static(path.join(__dirname, "public")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "app.html")));

// --------------------------- Эхний өгөгдөл (seed) ---------------------------
async function seedIfEmpty() {
  const { rows } = await pool.query("SELECT COUNT(*)::int AS c FROM users");
  if (rows[0].c > 0) return;

  const adminUser = (process.env.ADMIN_USER || "admin").toLowerCase();
  const adminPass = process.env.ADMIN_PASSWORD || "Kvant2026!";
  const hash = await bcrypt.hash(adminPass, 10);
  await pool.query(
    "INSERT INTO users (username,name,password,role) VALUES ($1,$2,$3,'admin')",
    [adminUser, "Админ", hash]
  );
  console.log(`✓ Админ хэрэглэгч үүслээ:  нэр="${adminUser}"  нууц үг="${adminPass}"`);
  console.log("  (Эхний удаа нэвтэрсний дараа нууц үгээ солино уу.)");

  // Жишээ ажлууд — энэ сарын огноогоор
  const now = new Date();
  const y = now.getFullYear();
  const m = now.getMonth();
  const dim = new Date(y, m + 1, 0).getDate();
  const pad = (n) => (n < 10 ? "0" + n : "" + n);
  const d = (n) => `${y}-${pad(m + 1)}-${pad(Math.min(Math.max(n, 1), dim))}`;
  const samples = [
    ["БЕЛАЗ-7555","Тяговый двигатель ДК-724А","Их засвар — ороомог бүрэн солих","Цахилгаан баг №1","Б.Ганбаатар","Зэс ороомог, изоляцийн лак МЛ-92, подшипник 6320",d(2),d(11),"prog"],
    ["БЕЛАЗ-75131","Мотор-колесо МК-3510","Подшипник солих, тос сэлбэх","Механик баг","Д.Мөнхбат","Подшипник 32222, редукторын тос 80W-90",d(4),d(8),"done"],
    ["БЕЛАЗ-7513","Тяговый генератор ГСТ-2000","Коллектор зүлгэх, щётка солих","Цахилгаан баг №2","Ц.Отгонбаяр","Графит щётка ЭГ-74, коллектор пласт",d(6),d(13),"prog"],
    ["БЕЛАЗ-7555","Инвертор IGBT-модуль","Онош — тусгаарлагч эсэргүүцэл хэмжих","Электроник баг","С.Энхжаргал","Мегаомметр, IGBT модуль (нөөц)",d(9),d(10),"wait"],
    ["БЕЛАЗ-75306","Тяговый двигатель ЭК-590","Изоляц сэргээх, вакуум шүршилт","Цахилгаан баг №1","Б.Ганбаатар","Компаунд, вакуум насос",d(12),d(20),"plan"],
    ["БЕЛАЗ-75131","Мотор-колесо МК-3512","Их засвар — редуктор задлан үзлэг","Механик баг","Д.Мөнхбат","Сателлит араа, сальник иж бүрдэл",d(14),d(24),"plan"],
    ["БЕЛАЗ-7513","Тяговый двигатель ДК-724Б","Якорь балансжуулах","Цахилгаан баг №2","Ц.Отгонбаяр","Балансын жин, подшипник 6322",d(16),d(21),"plan"],
    ["БЕЛАЗ-75306","Цэнэглэгч төхөөрөмж","Хүлээн авах туршилт, ачаалал өгөх","Электроник баг","С.Энхжаргал","Ачааллын реостат, хэмжих хэрэгсэл",d(18),d(19),"delay"],
    ["БЕЛАЗ-7555","Мотор-колесо МК-3510","Ороомог хатаах, лакдах","Цахилгаан баг №1","Б.Ганбаатар","Хатаах зуух, изоляцийн лак",d(22),d(27),"plan"],
    ["БЕЛАЗ-75131","Тяговый генератор ГСТ-2000","Профилактик үзлэг, тоос цэвэрлэгээ","Механик баг","Д.Мөнхбат","Шахсан агаар, тусгай уусмал",d(25),d(28),"plan"],
  ];
  for (const s of samples) {
    await pool.query(
      `INSERT INTO tasks (id,machine,unit,work,team,lead,parts,start_date,end_date,status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [newId(), ...s]
    );
  }
  console.log("✓ Жишээ ажлууд нэмэгдлээ.");
}

// --------------------------------- Эхлүүлэх ---------------------------------
(async () => {
  try {
    await init();
    await seedIfEmpty();
    app.listen(PORT, () => console.log(`✓ Сервер ажиллаж байна:  http://localhost:${PORT}`));
  } catch (e) {
    console.error("Эхлүүлэхэд алдаа гарлаа:", e);
    process.exit(1);
  }
})();
