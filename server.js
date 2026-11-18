const express=require("express"),{DatabaseSync}=require("node:sqlite"),bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken"),multer=require("multer"),cookie=require("cookie-parser"),path=require("path"),fs=require("fs"),crypto=require("crypto");
const PROD=process.env.NODE_ENV==="production",DATA=process.env.DATA_DIR||path.join(__dirname,"data");
if(PROD&&!process.env.JWT_SECRET)throw new Error("Set JWT_SECRET");
const SECRET=process.env.JWT_SECRET||"dev-secret",ADMIN=(process.env.ADMIN_EMAIL||"").toLowerCase();
["photos","docs"].forEach(d=>fs.mkdirSync(path.join(DATA,d),{recursive:true}));
const db=new DatabaseSync(path.join(DATA,"pawmate.db"));db.exec("pragma journal_mode=WAL;pragma foreign_keys=ON");
db.exec(`
create table if not exists users(id integer primary key,email text unique,phone text unique,name text not null,pass text,created text default current_timestamp);
create table if not exists otps(phone text primary key,hash text not null,expires integer not null,tries integer not null default 0,sent integer not null,n integer not null,win integer not null);
create table if not exists dogs(id text primary key,owner_id integer not null references users(id) on delete cascade,name text not null,vis text not null,breed text,sex text,age text,city text,temperament text,health text,vaccination text,pedigree text,contact text,address text,photo text,created text default current_timestamp);
create table if not exists docs(id integer primary key,dog_id text not null references dogs(id) on delete cascade,type text not null,file text not null,orig text,status text not null default 'pending',created text default current_timestamp);
create table if not exists requests(id integer primary key,from_dog text not null references dogs(id) on delete cascade,to_dog text not null references dogs(id) on delete cascade,status text not null default 'pending',created text default current_timestamp,unique(from_dog,to_dog));
create table if not exists messages(id integer primary key,req_id integer not null references requests(id) on delete cascade,sender_id integer not null references users(id),body text not null,created text default current_timestamp);`);
db.exec(`create table if not exists resets(user_id integer primary key references users(id) on delete cascade,hash text not null,expires integer not null);
create table if not exists blocks(blocker integer not null references users(id) on delete cascade,blocked integer not null references users(id) on delete cascade,created text default current_timestamp,primary key(blocker,blocked));
create table if not exists reports(id integer primary key,reporter integer not null references users(id) on delete cascade,reported integer not null references users(id) on delete cascade,dog_id text,reason text not null,details text,status text not null default 'open',created text default current_timestamp);`);
if(!db.prepare("select 1 from pragma_table_info('users') where name='suspended'").get())db.exec("alter table users add column suspended integer not null default 0");
const COLS=["breed","sex","age","city","temperament","health","vaccination","pedigree","contact","address"],DOCS=["Vaccination certificate","Vet health check","Pedigree papers"];
const DEF={breed:"public",sex:"public",age:"public",city:"public",temperament:"public",health:"matches",vaccination:"public",pedigree:"matches",contact:"matches",address:"private",photo:"public"};
const IMG=["image/jpeg","image/png","image/webp"],EXT={"image/jpeg":".jpg","image/png":".png","image/webp":".webp","application/pdf":".pdf"};
const up=(dir,types)=>multer({storage:multer.diskStorage({destination:path.join(DATA,dir),filename:(q,f,cb)=>cb(null,crypto.randomUUID()+EXT[f.mimetype])}),limits:{fileSize:5e6},fileFilter:(q,f,cb)=>types.includes(f.mimetype)?cb(null,true):cb(new Error("Unsupported file type"))});
const rm=(dir,f)=>f&&fs.unlink(path.join(DATA,dir,path.basename(f)),()=>{});
const app=express();app.set("trust proxy",1);app.use(express.json({limit:"50kb"}),cookie());
const hits={},limit=(q,r,n)=>{const k=q.ip,c=hits[k]=(hits[k]||0)+1;setTimeout(()=>hits[k]--,6e5);c>25?r.status(429).json({error:"Too many attempts. Try again in a few minutes."}):n()};
const setc=(r,u)=>r.cookie("t",jwt.sign({id:u.id},SECRET,{expiresIn:"30d"}),{httpOnly:true,sameSite:"lax",secure:PROD,maxAge:2592e6});
const isAdmin=u=>!!ADMIN&&u.email===ADMIN;
const pu=u=>({id:u.id,name:u.name,email:u.email,phone:u.phone,admin:isAdmin(u)});
app.use((q,r,n)=>{try{q.u=db.prepare("select id,email,name from users where id=? and suspended=0").get(jwt.verify(q.cookies.t,SECRET).id)}catch{}n()});
const need=(q,r,n)=>q.u?n():r.status(401).json({error:"Please log in"});
const admin=(q,r,n)=>q.u&&isAdmin(q.u)?n():r.sendStatus(403);
app.post("/api/signup",limit,(q,r)=>{const{name,email,password}=q.body,e=String(email||"").trim().toLowerCase();
 if(!String(name||"").trim()||!/^\S+@\S+\.\S+$/.test(e)||String(password||"").length<8)return r.status(400).json({error:"Enter your name, a valid email and a password of 8+ characters"});
 if(ADMIN&&e===ADMIN)return r.status(400).json({error:"That email can’t be used"});
 if(db.prepare("select 1 from users where email=?").get(e))return r.status(400).json({error:"That email is already registered"});
 const id=db.prepare("insert into users(email,name,pass) values(?,?,?)").run(e,String(name).trim().slice(0,60),bcrypt.hashSync(password,10)).lastInsertRowid;
 const u={id,email:e,name:String(name).trim()};setc(r,u);r.json({user:pu(u)})});
app.post("/api/login",limit,(q,r)=>{const u=db.prepare("select * from users where email=?").get(String(q.body.email||"").trim().toLowerCase());
 if(!u||!u.pass||!bcrypt.compareSync(String(q.body.password||""),u.pass))return r.status(400).json({error:"Wrong email or password"});if(u.suspended)return r.status(403).json({error:"This account has been suspended"});if(isAdmin(u))return r.status(403).json({error:"Admins sign in at /admin"});setc(r,u);r.json({user:pu(u)})});
app.post("/api/logout",(q,r)=>{r.clearCookie("t");r.json({})});
// admin: email + password only, account created from environment variables
if(ADMIN&&process.env.ADMIN_PASSWORD){const h=bcrypt.hashSync(process.env.ADMIN_PASSWORD,10);db.prepare("select id from users where email=?").get(ADMIN)?db.prepare("update users set pass=? where email=?").run(h,ADMIN):db.prepare("insert into users(email,name,pass) values(?,?,?)").run(ADMIN,"Admin",h)}
app.post("/api/admin/login",limit,(q,r)=>{const e=String(q.body.email||"").trim().toLowerCase(),u=ADMIN&&e===ADMIN&&db.prepare("select * from users where email=?").get(e);
 if(!u||!u.pass||!bcrypt.compareSync(String(q.body.password||""),u.pass))return r.status(400).json({error:"Wrong email or password"});setc(r,u);r.json({user:pu(u)})});
// phone login with one-time code
const normPhone=s=>{let d=String(s||"").replace(/[^\d+]/g,"");if(d[0]==="+")d=d.slice(1);else if(d.length===10)d="91"+d;else if(d.length===11&&d[0]==="0")d="91"+d.slice(1);return /^\d{11,15}$/.test(d)?"+"+d:null};
const hashOtp=(p,c)=>crypto.createHash("sha256").update(p+c+SECRET).digest("hex");
const same=(a,b)=>a.length===b.length&&crypto.timingSafeEqual(Buffer.from(a),Buffer.from(b));
async function sendSms(to,text){const{TWILIO_SID:s,TWILIO_TOKEN:t,TWILIO_FROM:f}=process.env;
 if(!s||!t||!f){if(PROD)throw new Error("Phone login isn’t set up yet. Please use email.");console.log(`[TEST SMS to ${to}] ${text}`);return true}
 const r=await fetch(`https://api.twilio.com/2010-04-01/Accounts/${s}/Messages.json`,{method:"POST",headers:{Authorization:"Basic "+Buffer.from(s+":"+t).toString("base64"),"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({To:to,From:f,Body:text})});
 if(!r.ok)throw new Error("Couldn’t send the code. Please try again.");return false}
app.post("/api/otp/send",limit,async(q,r)=>{const p=normPhone(q.body.phone);if(!p)return r.status(400).json({error:"Enter a valid mobile number"});
 const o=db.prepare("select * from otps where phone=?").get(p),now=Date.now();let n=1,win=now;
 if(o&&now-o.sent<30000)return r.status(429).json({error:"Wait 30 seconds before asking for another code"});
 if(o&&now-o.win<36e5){n=o.n+1;win=o.win;if(n>5)return r.status(429).json({error:"Too many codes requested. Try again in an hour."})}
 const code=String(crypto.randomInt(0,1e6)).padStart(6,"0");
 try{const dev=await sendSms(p,`Your PawMate code is ${code}. It expires in 10 minutes.`);
  db.prepare("insert or replace into otps(phone,hash,expires,tries,sent,n,win) values(?,?,?,0,?,?,?)").run(p,hashOtp(p,code),now+6e5,now,n,win);r.json({ok:true,...(dev?{devCode:code}:{})})}
 catch(e){r.status(503).json({error:e.message})}});
app.post("/api/otp/verify",limit,(q,r)=>{const p=normPhone(q.body.phone),code=String(q.body.code||"").trim(),o=p&&db.prepare("select * from otps where phone=?").get(p);
 if(!o||o.expires<Date.now()||o.tries>=5)return r.status(400).json({error:"That code has expired. Ask for a new one."});
 if(!same(o.hash,hashOtp(p,code))){db.prepare("update otps set tries=tries+1 where phone=?").run(p);return r.status(400).json({error:"Wrong code"})}
 let u=db.prepare("select * from users where phone=?").get(p);if(u&&u.suspended)return r.status(403).json({error:"This account has been suspended"});
 if(!u){const name=String(q.body.name||"").trim().slice(0,60);if(!name)return r.status(400).json({error:"Enter your name to finish creating your account"});
  const id=db.prepare("insert into users(phone,name) values(?,?)").run(p,name).lastInsertRowid;u={id,phone:p,name,email:null}}
 db.prepare("delete from otps where phone=?").run(p);setc(r,u);r.json({user:pu(u)})});

app.get("/api/me",need,(q,r)=>r.json({user:pu(q.u)}));
// privacy
const level=(d,uid)=>d.owner_id===uid?"me":db.prepare("select 1 from requests r where r.status='accepted' and ((r.to_dog=@d and r.from_dog in (select id from dogs where owner_id=@u)) or (r.from_dog=@d and r.to_dog in (select id from dogs where owner_id=@u)))").get({d:d.id,u:uid})?"match":"pub";
const allowed=(d,k,l)=>{const v=JSON.parse(d.vis)[k];return l==="me"||v==="public"||(v==="matches"&&l==="match")};
function ser(d,uid){const l=level(d,uid),docs=db.prepare("select id,type,status from docs where dog_id=?").all(d.id),n=docs.filter(x=>x.status==="approved").length,o={id:d.id,name:d.name,verified:n>=2,approved:n,hidden:[]};
 for(const k of [...COLS,"photo"]){if(!d[k])continue;if(allowed(d,k,l))o[k]=k==="photo"?`/api/dogs/${d.id}/photo?v=${d.photo}`:d[k];else o.hidden.push(k)}
 if(l==="me"){o.vis=JSON.parse(d.vis);o.docs=docs}return o}
const clean=b=>{const d={name:String(b.name||"").trim().slice(0,60),vis:{}};for(const k of COLS)d[k]=String(b[k]||"").trim().slice(0,200);for(const k of Object.keys(DEF))d.vis[k]=["public","matches","private"].includes(b.vis?.[k])?b.vis[k]:DEF[k];return d};
const own=(q,r,n)=>{q.dog=db.prepare("select * from dogs where id=? and owner_id=?").get(q.params.id,q.u.id);q.dog?n():r.sendStatus(404)};
app.get("/api/my/dogs",need,(q,r)=>r.json({dogs:db.prepare("select * from dogs where owner_id=? order by created").all(q.u.id).map(d=>ser(d,q.u.id))}));
app.post("/api/my/dogs",need,(q,r)=>{const d=clean(q.body);if(!d.name||!d.breed||!d.sex)return r.status(400).json({error:"Name, breed and sex are required"});
 const id=crypto.randomUUID();db.prepare(`insert into dogs(id,owner_id,name,vis,${COLS}) values(?,?,?,?,${COLS.map(()=>"?")})`).run(id,q.u.id,d.name,JSON.stringify(d.vis),...COLS.map(c=>d[c]));r.json({id})});
app.put("/api/my/dogs/:id",need,own,(q,r)=>{const d=clean(q.body);if(!d.name||!d.breed||!d.sex)return r.status(400).json({error:"Name, breed and sex are required"});
 db.prepare(`update dogs set name=?,vis=?,${COLS.map(c=>c+"=?")} where id=?`).run(d.name,JSON.stringify(d.vis),...COLS.map(c=>d[c]),q.dog.id);r.json({})});
app.delete("/api/my/dogs/:id",need,own,(q,r)=>{db.prepare("select file from docs where dog_id=?").all(q.dog.id).forEach(x=>rm("docs",x.file));rm("photos",q.dog.photo);db.prepare("delete from dogs where id=?").run(q.dog.id);r.json({})});
app.post("/api/my/dogs/:id/photo",need,own,up("photos",IMG).single("photo"),(q,r)=>{if(!q.file)return r.status(400).json({error:"Choose an image"});rm("photos",q.dog.photo);db.prepare("update dogs set photo=? where id=?").run(q.file.filename,q.dog.id);r.json({})});
app.post("/api/my/dogs/:id/docs",need,own,up("docs",[...IMG,"application/pdf"]).single("file"),(q,r)=>{
 if(!q.file)return r.status(400).json({error:"Choose a file"});if(!DOCS.includes(q.body.type)){rm("docs",q.file.filename);return r.status(400).json({error:"Unknown document type"})}
 db.prepare("select file from docs where dog_id=? and type=?").all(q.dog.id,q.body.type).forEach(x=>rm("docs",x.file));db.prepare("delete from docs where dog_id=? and type=?").run(q.dog.id,q.body.type);
 db.prepare("insert into docs(dog_id,type,file,orig) values(?,?,?,?)").run(q.dog.id,q.body.type,q.file.filename,String(q.file.originalname).slice(0,80));r.json({})});
app.get("/api/dogs/:id/photo",need,(q,r)=>{const d=db.prepare("select * from dogs where id=?").get(q.params.id);if(!d||!d.photo||!allowed(d,"photo",level(d,q.u.id)))return r.sendStatus(404);r.set("Cache-Control","private, max-age=86400").sendFile(path.join(DATA,"photos",path.basename(d.photo)))});
app.get("/api/docs/:id/file",need,(q,r)=>{const x=db.prepare("select docs.file,dogs.owner_id from docs join dogs on dogs.id=docs.dog_id where docs.id=?").get(q.params.id);if(!x||(x.owner_id!==q.u.id&&!isAdmin(q.u)))return r.sendStatus(404);r.sendFile(path.join(DATA,"docs",path.basename(x.file)))});
app.get("/api/dogs",need,(q,r)=>{let a=db.prepare("select * from dogs where owner_id!=@u and owner_id not in (select blocked from blocks where blocker=@u union select blocker from blocks where blocked=@u) and owner_id not in (select id from users where suspended=1) order by created desc").all({u:q.u.id}).map(d=>ser(d,q.u.id));const Q=q.query,low=s=>String(s||"").toLowerCase();
 if(Q.breed)a=a.filter(d=>low(d.breed).includes(low(Q.breed)));if(Q.sex)a=a.filter(d=>d.sex===Q.sex);if(Q.verified)a=a.filter(d=>d.verified);
 if(Q.forDog){const m=db.prepare("select * from dogs where id=? and owner_id=?").get(Q.forDog,q.u.id);if(m)a=a.filter(d=>low(d.breed)===low(m.breed)&&d.sex&&d.sex!==m.sex)}
 r.json({dogs:a.sort((x,y)=>y.verified-x.verified)})});
// requests and chat
app.post("/api/requests",need,(q,r)=>{const f=db.prepare("select * from dogs where id=? and owner_id=?").get(q.body.fromDog,q.u.id),t=db.prepare("select * from dogs where id=? and owner_id!=?").get(q.body.toDog,q.u.id);
 if(!f||!t)return r.status(400).json({error:"Choose one of your dogs and another owner’s dog"});
 if(db.prepare("select 1 from blocks where (blocker=@a and blocked=@b) or (blocker=@b and blocked=@a)").get({a:q.u.id,b:t.owner_id}))return r.status(400).json({error:"You can’t send a request to this owner"});
 if(db.prepare("select 1 from requests where (from_dog=@a and to_dog=@b) or (from_dog=@b and to_dog=@a)").get({a:f.id,b:t.id}))return r.status(400).json({error:"A request between these dogs already exists"});
 db.prepare("insert into requests(from_dog,to_dog) values(?,?)").run(f.id,t.id);r.json({})});
app.get("/api/requests",need,(q,r)=>{const rows=db.prepare("select r.*,f.owner_id fo,t.owner_id tw from requests r join dogs f on f.id=r.from_dog join dogs t on t.id=r.to_dog where (f.owner_id=@u or t.owner_id=@u) and r.status!='blocked' order by r.id desc").all({u:q.u.id});
 r.json({requests:rows.map(x=>{const out=x.fo===q.u.id,mine=db.prepare("select * from dogs where id=?").get(out?x.from_dog:x.to_dog),other=db.prepare("select * from dogs where id=?").get(out?x.to_dog:x.from_dog);return{id:x.id,status:x.status,dir:out?"out":"in",mine:{id:mine.id,name:mine.name},other:ser(other,q.u.id)}})})});
app.post("/api/requests/:id/respond",need,(q,r)=>{const x=db.prepare("select r.*,t.owner_id tw from requests r join dogs t on t.id=r.to_dog where r.id=?").get(q.params.id);
 if(!x||x.tw!==q.u.id||x.status!=="pending")return r.sendStatus(404);db.prepare("update requests set status=? where id=?").run(q.body.accept?"accepted":"declined",x.id);r.json({})});
const thread=(q,r,n)=>{const x=db.prepare("select r.*,f.owner_id fo,t.owner_id tw from requests r join dogs f on f.id=r.from_dog join dogs t on t.id=r.to_dog where r.id=?").get(q.params.id);
 if(!x||(x.fo!==q.u.id&&x.tw!==q.u.id))return r.sendStatus(404);if(x.status!=="accepted")return r.status(403).json({error:"Chat opens once the request is accepted"});n()};
app.get("/api/requests/:id/messages",need,thread,(q,r)=>r.json({messages:db.prepare("select id,sender_id=? as mine,body,created from messages where req_id=? and id>? order by id").all(q.u.id,q.params.id,Number(q.query.after)||0)}));
app.post("/api/requests/:id/messages",need,thread,(q,r)=>{const b=String(q.body.body||"").trim().slice(0,1000);if(!b)return r.status(400).json({error:"Write a message first"});db.prepare("insert into messages(req_id,sender_id,body) values(?,?,?)").run(q.params.id,q.u.id,b);r.json({})});
// admin
app.get("/api/admin/docs",need,admin,(q,r)=>r.json({docs:db.prepare("select docs.id,docs.type,docs.orig,dogs.name dog,users.email owner from docs join dogs on dogs.id=docs.dog_id join users on users.id=dogs.owner_id where docs.status='pending' order by docs.id").all()}));
app.post("/api/admin/docs/:id",need,admin,(q,r)=>{db.prepare("update docs set status=? where id=?").run(q.body.approve?"approved":"rejected",q.params.id);r.json({})});

// password reset by email
const BASE=(process.env.BASE_URL||`http://localhost:${process.env.PORT||3000}`).replace(/\/$/,"");
const mailer=process.env.SMTP_HOST?require("nodemailer").createTransport({host:process.env.SMTP_HOST,port:+process.env.SMTP_PORT||587,secure:+process.env.SMTP_PORT===465,auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}}):null;
async function sendMail(to,subject,text){if(!mailer){console.log(`[TEST EMAIL to ${to}] ${subject}\n${text}`);return}await mailer.sendMail({from:process.env.MAIL_FROM||process.env.SMTP_USER,to,subject,text})}
app.post("/api/password/forgot",limit,async(q,r)=>{if(PROD&&!mailer)return r.status(503).json({error:"Password reset by email isn’t set up yet."});
 const e=String(q.body.email||"").trim().toLowerCase(),u=e&&e!==ADMIN&&db.prepare("select * from users where email=?").get(e);
 try{if(u&&u.pass){const t=crypto.randomBytes(32).toString("hex");db.prepare("insert or replace into resets(user_id,hash,expires) values(?,?,?)").run(u.id,crypto.createHash("sha256").update(t).digest("hex"),Date.now()+36e5);
  await sendMail(e,"Reset your PawMate password",`Hi ${u.name},\n\nOpen this link to choose a new password (valid for 1 hour):\n${BASE}/reset#${t}\n\nIf you didn’t ask for this, you can ignore this email.`)}}catch(err){console.error("Email failed:",err.message)}
 r.json({ok:true})});
app.post("/api/password/reset",limit,(q,r)=>{const t=String(q.body.token||""),pw=String(q.body.password||"");if(pw.length<8)return r.status(400).json({error:"Password must be 8+ characters"});
 const x=t&&db.prepare("select * from resets where hash=?").get(crypto.createHash("sha256").update(t).digest("hex"));
 if(!x||x.expires<Date.now())return r.status(400).json({error:"This reset link has expired. Ask for a new one."});
 db.prepare("update users set pass=? where id=?").run(bcrypt.hashSync(pw,10),x.user_id);db.prepare("delete from resets where user_id=?").run(x.user_id);r.json({ok:true})});
// blocking and reporting
const REASONS=["Fake or misleading profile","Scam or asking for money","Harassment or abuse","Unsafe breeding or animal cruelty","Other"];
const ownerOf=id=>(db.prepare("select owner_id o from dogs where id=?").get(String(id))||{}).o;
const PAIR="(from_dog in (select id from dogs where owner_id=@a) and to_dog in (select id from dogs where owner_id=@b)) or (from_dog in (select id from dogs where owner_id=@b) and to_dog in (select id from dogs where owner_id=@a))";
app.post("/api/block",need,(q,r)=>{const o=ownerOf(q.body.dogId);if(!o||o===q.u.id)return r.status(400).json({error:"You can’t block this owner"});
 db.prepare("insert or ignore into blocks(blocker,blocked) values(?,?)").run(q.u.id,o);db.prepare(`update requests set status='blocked' where ${PAIR}`).run({a:q.u.id,b:o});r.json({})});
app.get("/api/blocks",need,(q,r)=>r.json({blocks:db.prepare("select users.id,users.name from blocks join users on users.id=blocks.blocked where blocker=?").all(q.u.id)}));
app.post("/api/unblock",need,(q,r)=>{const o=Number(q.body.userId)||0;db.prepare("delete from blocks where blocker=? and blocked=?").run(q.u.id,o);db.prepare(`delete from requests where status='blocked' and (${PAIR})`).run({a:q.u.id,b:o});r.json({})});
app.post("/api/report",need,(q,r)=>{const o=ownerOf(q.body.dogId);if(!o||o===q.u.id||!REASONS.includes(q.body.reason))return r.status(400).json({error:"Choose a reason for the report"});
 if(db.prepare("select count(*) c from reports where reporter=? and created>datetime('now','-1 day')").get(q.u.id).c>=10)return r.status(429).json({error:"Report limit reached for today"});
 if(db.prepare("select 1 from reports where reporter=? and dog_id=? and status='open'").get(q.u.id,String(q.body.dogId)))return r.status(400).json({error:"You already reported this profile. We’ll review it."});
 db.prepare("insert into reports(reporter,reported,dog_id,reason,details) values(?,?,?,?,?)").run(q.u.id,o,String(q.body.dogId),q.body.reason,String(q.body.details||"").slice(0,500));r.json({})});
app.get("/api/admin/reports",need,admin,(q,r)=>r.json({reports:db.prepare("select reports.id,reports.reason,reports.details,dogs.name dog,coalesce(ru.email,ru.phone) owner,rp.name reporter,(select count(*) from reports x where x.reported=reports.reported and x.status='open') total from reports join users ru on ru.id=reports.reported join users rp on rp.id=reports.reporter left join dogs on dogs.id=reports.dog_id where reports.status='open' order by reports.id").all(),suspended:db.prepare("select id,name,coalesce(email,phone) contact from users where suspended=1").all()}));
app.post("/api/admin/reports/:id",need,admin,(q,r)=>{const x=db.prepare("select * from reports where id=?").get(q.params.id);if(!x)return r.sendStatus(404);
 if(q.body.suspend){db.prepare("update users set suspended=1 where id=?").run(x.reported);db.prepare("update reports set status='actioned' where reported=? and status='open'").run(x.reported)}else db.prepare("update reports set status='dismissed' where id=?").run(x.id);r.json({})});
app.post("/api/admin/users/:id/restore",need,admin,(q,r)=>{db.prepare("update users set suspended=0 where id=?").run(q.params.id);r.json({})});
app.use(express.static(path.join(__dirname,"public"),{extensions:["html"]}));
app.use((e,q,r,n)=>r.status(400).json({error:e.message}));
app.listen(process.env.PORT||3000,()=>console.log("PawMate running"));
