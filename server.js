const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const helmet=require("helmet");
const path=require("path");

const app=express();
const db=new Database("demo.sqlite");
const PORT=process.env.PORT||3000;
const SESSION_SECRET=process.env.SESSION_SECRET||"CHANGE_THIS_DEMO_SECRET";

app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({secret:SESSION_SECRET,resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:"lax",secure:false,maxAge:86400000}}));
app.use(express.static(path.join(__dirname,"public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, status TEXT DEFAULT 'active', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admins(
 id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS wallets(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, currency TEXT NOT NULL,
 balance REAL DEFAULT 0, UNIQUE(user_id,currency)
);
CREATE TABLE IF NOT EXISTS deposits(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, currency TEXT NOT NULL,
 amount REAL NOT NULL, address TEXT, status TEXT DEFAULT 'pending', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS withdrawals(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, currency TEXT NOT NULL,
 amount REAL NOT NULL, address TEXT NOT NULL, fee REAL DEFAULT 0, status TEXT DEFAULT 'pending',
 note TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS transactions(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL,
 currency TEXT NOT NULL, amount REAL NOT NULL, status TEXT NOT NULL, note TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS pnl(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, currency TEXT NOT NULL,
 amount REAL NOT NULL, note TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS support_tickets(
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, subject TEXT NOT NULL,
 message TEXT NOT NULL, status TEXT DEFAULT 'open', created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs(
 id INTEGER PRIMARY KEY AUTOINCREMENT, admin_id INTEGER, user_id INTEGER, action TEXT NOT NULL,
 currency TEXT, amount REAL, previous_balance REAL, new_balance REAL, reason TEXT,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
`);

const defaults={
 platform_name:"walmartprodct",
 maintenance_mode:"0",
 support_email:"support@example.test",
 demo_fee:"0.5",
 withdrawal_limit:"10000",
 supported_currencies:"USDT,ETH"
};
for(const [k,v] of Object.entries(defaults))
  db.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)").run(k,v);

const adminEmail="admin@walmartprodct.demo";
if(!db.prepare("SELECT id FROM admins WHERE email=?").get(adminEmail)){
  db.prepare("INSERT INTO admins(email,password_hash) VALUES(?,?)").run(adminEmail,bcrypt.hashSync("DemoAdmin123!",10));
}

function auth(req,res,next){ if(!req.session.userId) return res.status(401).json({error:"Login required"}); next(); }
function admin(req,res,next){ if(!req.session.adminId) return res.status(403).json({error:"Admin access required"}); next(); }
function setting(k){return db.prepare("SELECT value FROM settings WHERE key=?").get(k)?.value}
function wallet(userId,currency){
  return db.prepare("SELECT * FROM wallets WHERE user_id=? AND currency=?").get(userId,currency);
}
function ensureWallets(userId){
  for(const c of ["USDT","ETH"]) db.prepare("INSERT OR IGNORE INTO wallets(user_id,currency,balance) VALUES(?,?,0)").run(userId,c);
}

app.post("/api/register",(req,res)=>{
  const {name,email,password}=req.body;
  if(!name||!email||!password||password.length<6) return res.status(400).json({error:"Name, email and 6+ character password required"});
  try{
    const info=db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name,email.toLowerCase(),bcrypt.hashSync(password,10));
    ensureWallets(info.lastInsertRowid); req.session.userId=info.lastInsertRowid;
    res.json({ok:true});
  }catch(e){res.status(400).json({error:"Email already registered"});}
});
app.post("/api/login",(req,res)=>{
  const u=db.prepare("SELECT * FROM users WHERE email=?").get((req.body.email||"").toLowerCase());
  if(!u||!bcrypt.compareSync(req.body.password||"",u.password_hash)||u.status!=="active") return res.status(401).json({error:"Invalid credentials or suspended demo account"});
  req.session.userId=u.id; res.json({ok:true});
});
app.post("/api/admin/login",(req,res)=>{
  const a=db.prepare("SELECT * FROM admins WHERE email=?").get((req.body.email||"").toLowerCase());
  if(!a||!bcrypt.compareSync(req.body.password||"",a.password_hash)) return res.status(401).json({error:"Invalid admin credentials"});
  req.session.adminId=a.id; res.json({ok:true});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/me",auth,(req,res)=>{
  const u=db.prepare("SELECT id,name,email,status,created_at FROM users WHERE id=?").get(req.session.userId);
  const wallets=db.prepare("SELECT currency,balance FROM wallets WHERE user_id=?").all(u.id);
  const tx=db.prepare("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 8").all(u.id);
  const profit=db.prepare("SELECT COALESCE(SUM(amount),0) total FROM pnl WHERE user_id=?").get(u.id).total;
  res.json({user:u,wallets,profit,transactions:tx,maintenance:setting("maintenance_mode")==="1"});
});

app.post("/api/deposit",auth,(req,res)=>{
  if(setting("maintenance_mode")==="1") return res.status(503).json({error:"Demo deposits are temporarily disabled"});
  const {currency,amount}=req.body; const n=Number(amount);
  if(!["USDT","ETH"].includes(currency)||!Number.isFinite(n)||n<=0) return res.status(400).json({error:"Invalid demo deposit"});
  const address=`DEMO-${currency}-ADDRESS-${Math.random().toString(36).slice(2,10).toUpperCase()}`;
  const d=db.prepare("INSERT INTO deposits(user_id,currency,amount,address,status) VALUES(?,?,?,?,?)").run(req.session.userId,currency,n,address,"pending");
  db.prepare("INSERT INTO transactions(user_id,type,currency,amount,status,note) VALUES(?,?,?,?,?,?)").run(req.session.userId,"deposit",currency,n,"pending","Simulated test deposit");
  res.json({ok:true,id:d.lastInsertRowid,address});
});

app.post("/api/withdraw",auth,(req,res)=>{
  if(setting("maintenance_mode")==="1") return res.status(503).json({error:"Demo withdrawals are temporarily disabled"});
  const {currency,amount,address}=req.body; const n=Number(amount);
  if(!["USDT","ETH"].includes(currency)||!address||!Number.isFinite(n)||n<=0) return res.status(400).json({error:"Invalid demo withdrawal"});
  if(n>Number(setting("withdrawal_limit"))) return res.status(400).json({error:"Demo withdrawal limit exceeded"});
  const w=wallet(req.session.userId,currency);
  if(!w||w.balance<n) return res.status(400).json({error:"Insufficient demo balance"});
  const fee=Math.min(Number(setting("demo_fee")),n);
  db.prepare("UPDATE wallets SET balance=balance-? WHERE user_id=? AND currency=?").run(n,req.session.userId,currency);
  const r=db.prepare("INSERT INTO withdrawals(user_id,currency,amount,address,fee,status) VALUES(?,?,?,?,?,?)").run(req.session.userId,currency,n,address,fee,"pending");
  db.prepare("INSERT INTO transactions(user_id,type,currency,amount,status,note) VALUES(?,?,?,?,?,?)").run(req.session.userId,"withdrawal",currency,n,"pending","Simulated test withdrawal");
  res.json({ok:true,id:r.lastInsertRowid});
});

app.get("/api/transactions",auth,(req,res)=>res.json(db.prepare("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC").all(req.session.userId)));
app.get("/api/tickets",auth,(req,res)=>res.json(db.prepare("SELECT * FROM support_tickets WHERE user_id=? ORDER BY id DESC").all(req.session.userId)));
app.post("/api/tickets",auth,(req,res)=>{
  if(!req.body.subject||!req.body.message) return res.status(400).json({error:"Subject and message required"});
  db.prepare("INSERT INTO support_tickets(user_id,subject,message) VALUES(?,?,?)").run(req.session.userId,req.body.subject,req.body.message);
  res.json({ok:true});
});

app.get("/api/admin/overview",admin,(req,res)=>{
  const one=q=>db.prepare(q).get();
  res.json({
    users:one("SELECT COUNT(*) c FROM users").c,
    balances:one("SELECT COALESCE(SUM(balance),0) c FROM wallets").c,
    deposits:one("SELECT COALESCE(SUM(amount),0) c FROM deposits").c,
    withdrawals:one("SELECT COALESCE(SUM(amount),0) c FROM withdrawals").c,
    pendingWithdrawals:one("SELECT COUNT(*) c FROM withdrawals WHERE status='pending'").c,
    pendingDeposits:one("SELECT COUNT(*) c FROM deposits WHERE status='pending'").c,
    activity:db.prepare("SELECT 'withdrawal' type,id,user_id,currency,amount,status,created_at FROM withdrawals UNION ALL SELECT 'deposit',id,user_id,currency,amount,status,created_at FROM deposits ORDER BY created_at DESC LIMIT 12").all()
  });
});
app.get("/api/admin/users",admin,(req,res)=>res.json(db.prepare("SELECT id,name,email,status,created_at FROM users ORDER BY id DESC").all()));
app.get("/api/admin/withdrawals",admin,(req,res)=>res.json(db.prepare("SELECT w.*,u.name,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.id DESC").all()));
app.get("/api/admin/deposits",admin,(req,res)=>res.json(db.prepare("SELECT d.*,u.name,u.email FROM deposits d JOIN users u ON u.id=d.user_id ORDER BY d.id DESC").all()));
app.get("/api/admin/balances",admin,(req,res)=>res.json(db.prepare("SELECT u.id,u.name,u.email,w.currency,w.balance FROM users u JOIN wallets w ON w.user_id=u.id ORDER BY u.id DESC").all()));
app.get("/api/admin/audit",admin,(req,res)=>res.json(db.prepare("SELECT a.*,u.name user_name,ad.email admin_email FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id LEFT JOIN admins ad ON ad.id=a.admin_id ORDER BY a.id DESC LIMIT 100").all()));

app.post("/api/admin/user-status",admin,(req,res)=>{
  db.prepare("UPDATE users SET status=? WHERE id=?").run(req.body.status,req.body.userId);
  res.json({ok:true});
});
app.post("/api/admin/balance",admin,(req,res)=>{
  const userId=Number(req.body.userId), currency=req.body.currency, amount=Number(req.body.amount), reason=req.body.reason||"Admin demo adjustment";
  if(!["USDT","ETH"].includes(currency)||!Number.isFinite(amount)) return res.status(400).json({error:"Invalid adjustment"});
  ensureWallets(userId); const w=wallet(userId,currency); const next=w.balance+amount;
  if(next<0) return res.status(400).json({error:"Balance cannot become negative"});
  db.prepare("UPDATE wallets SET balance=? WHERE user_id=? AND currency=?").run(next,userId,currency);
  db.prepare("INSERT INTO audit_logs(admin_id,user_id,action,currency,amount,previous_balance,new_balance,reason) VALUES(?,?,?,?,?,?,?,?)").run(req.session.adminId,userId,"balance_adjustment",currency,amount,w.balance,next,reason);
  res.json({ok:true});
});
app.post("/api/admin/withdrawal",admin,(req,res)=>{
  const {id,status,note}=req.body;
  if(!["pending","approved","rejected"].includes(status)) return res.status(400).json({error:"Invalid status"});
  const w=db.prepare("SELECT * FROM withdrawals WHERE id=?").get(id); if(!w) return res.status(404).json({error:"Not found"});
  if(status==="rejected" && w.status!=="rejected"){
    db.prepare("UPDATE wallets SET balance=balance+? WHERE user_id=? AND currency=?").run(w.amount,w.user_id,w.currency);
  }
  db.prepare("UPDATE withdrawals SET status=?,note=? WHERE id=?").run(status,note||"",id);
  db.prepare("UPDATE transactions SET status=? WHERE user_id=? AND type='withdrawal' AND currency=? AND amount=? ORDER BY id DESC LIMIT 1").run(status,w.user_id,w.currency,w.amount);
  res.json({ok:true});
});
app.post("/api/admin/settings",admin,(req,res)=>{
  for(const [k,v] of Object.entries(req.body||{})) if(defaults[k]!==undefined) db.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(k,String(v));
  res.json({ok:true});
});
app.get("/api/admin/settings",admin,(req,res)=>res.json(Object.fromEntries(db.prepare("SELECT key,value FROM settings").all().map(x=>[x.key,x.value]))));

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`DEMO platform running at http://localhost:${PORT}`));
