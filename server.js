const express=require("express"),{DatabaseSync}=require("node:sqlite"),bcrypt=require("bcryptjs"),jwt=require("jsonwebtoken"),multer=require("multer"),cookie=require("cookie-parser"),path=require("path"),fs=require("fs"),crypto=require("crypto");
const PROD=process.env.NODE_ENV==="production",DATA=process.env.DATA_DIR||path.join(__dirname,"data");
if(PROD&&!process.env.JWT_SECRET)throw new Error("Set JWT_SECRET");
const SECRET=process.env.JWT_SECRET||"dev-secret",ADMIN=(process.env.ADMIN_EMAIL||"").toLowerCase();
["photos","docs"].forEach(d=>fs.mkdirSync(path.join(DATA,d),{recursive:true}));
const db=new DatabaseSync(path.join(DATA,"pawmate.db"));db.exec("pragma journal_mode=WAL;pragma foreign_keys=ON");
db.exec(`
create table if not exists users(id integer primary key,email text unique not null,name text not null,pass text not null,created text default current_timestamp);
create table if not exists dogs(id text primary key,owner_id integer not null references users(id) on delete cascade,name text not null,vis text not null,breed text,sex text,age text,city text,temperament text,health text,vaccination text,pedigree text,contact text,address text,photo text,created text default current_timestamp);
create table if not exists docs(id integer primary key,dog_id text not null references dogs(id) on delete cascade,type text not null,file text not null,orig text,status text not null default 'pending',created text default current_timestamp);
create table if not exists requests(id integer primary key,from_dog text not null references dogs(id) on delete cascade,to_dog text not null references dogs(id) on delete cascade,status text not null default 'pending',created text default current_timestamp,unique(from_dog,to_dog));
create table if not exists messages(id integer primary key,req_id integer not null references requests(id) on delete cascade,sender_id integer not null references users(id),body text not null,created text default current_timestamp);`);
const COLS=["breed","sex","age","city","temperament","health","vaccination","pedigree","contact","address"],DOCS=["Vaccination certificate","Vet health check","Pedigree papers"];
const DEF={breed:"public",sex:"public",age:"public",city:"public",temperament:"public",health:"matches",vaccination:"public",pedigree:"matches",contact:"matches",address:"private",photo:"public"};
const IMG=["image/jpeg","image/png","image/webp"],EXT={"image/jpeg":".jpg","image/png":".png","image/webp":".webp","application/pdf":".pdf"};
const up=(dir,types)=>multer({storage:multer.diskStorage({destination:path.join(DATA,dir),filename:(q,f,cb)=>cb(null,crypto.randomUUID()+EXT[f.mimetype])}),limits:{fileSize:5e6},fileFilter:(q,f,cb)=>types.includes(f.mimetype)?cb(null,true):cb(new Error("Unsupported file type"))});
const rm=(dir,f)=>f&&fs.unlink(path.join(DATA,dir,path.basename(f)),()=>{});
const app=express();app.set("trust proxy",1);app.use(express.json({limit:"50kb"}),cookie());
const hits={},limit=(q,r,n)=>{const k=q.ip,c=hits[k]=(hits[k]||0)+1;setTimeout(()=>hits[k]--,6e5);c>25?r.status(429).json({error:"Too many attempts. Try again in a few minutes."}):n()};
const setc=(r,u)=>r.cookie("t",jwt.sign({id:u.id},SECRET,{expiresIn:"30d"}),{httpOnly:true,sameSite:"lax",secure:PROD,maxAge:2592e6});
const pu=u=>({id:u.id,name:u.name,email:u.email,admin:u.email===ADMIN});
app.use((q,r,n)=>{try{q.u=db.prepare("select id,email,name from users where id=?").get(jwt.verify(q.cookies.t,SECRET).id)}catch{}n()});
const need=(q,r,n)=>q.u?n():r.status(401).json({error:"Please log in"});
const admin=(q,r,n)=>q.u&&q.u.email===ADMIN?n():r.sendStatus(403);
app.post("/api/signup",limit,(q,r)=>{const{name,email,password}=q.body,e=String(email||"").trim().toLowerCase();
 if(!String(name||"").trim()||!/^\S+@\S+\.\S+$/.test(e)||String(password||"").length<8)return r.status(400).json({error:"Enter your name, a valid email and a password of 8+ characters"});
 if(db.prepare("select 1 from users where email=?").get(e))return r.status(400).json({error:"That email is already registered"});
 const id=db.prepare("insert into users(email,name,pass) values(?,?,?)").run(e,String(name).trim().slice(0,60),bcrypt.hashSync(password,10)).lastInsertRowid;
 const u={id,email:e,name:String(name).trim()};setc(r,u);r.json({user:pu(u)})});
app.post("/api/login",limit,(q,r)=>{const u=db.prepare("select * from users where email=?").get(String(q.body.email||"").trim().toLowerCase());
 if(!u||!bcrypt.compareSync(String(q.body.password||""),u.pass))return r.status(400).json({error:"Wrong email or password"});setc(r,u);r.json({user:pu(u)})});
app.post("/api/logout",(q,r)=>{r.clearCookie("t");r.json({})});
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
app.get("/api/docs/:id/file",need,(q,r)=>{const x=db.prepare("select docs.file,dogs.owner_id from docs join dogs on dogs.id=docs.dog_id where docs.id=?").get(q.params.id);if(!x||(x.owner_id!==q.u.id&&q.u.email!==ADMIN))return r.sendStatus(404);r.sendFile(path.join(DATA,"docs",path.basename(x.file)))});
app.get("/api/dogs",need,(q,r)=>{let a=db.prepare("select * from dogs where owner_id!=? order by created desc").all(q.u.id).map(d=>ser(d,q.u.id));const Q=q.query,low=s=>String(s||"").toLowerCase();
 if(Q.breed)a=a.filter(d=>low(d.breed).includes(low(Q.breed)));if(Q.sex)a=a.filter(d=>d.sex===Q.sex);if(Q.verified)a=a.filter(d=>d.verified);
 if(Q.forDog){const m=db.prepare("select * from dogs where id=? and owner_id=?").get(Q.forDog,q.u.id);if(m)a=a.filter(d=>low(d.breed)===low(m.breed)&&d.sex&&d.sex!==m.sex)}
 r.json({dogs:a.sort((x,y)=>y.verified-x.verified)})});
// requests and chat
app.post("/api/requests",need,(q,r)=>{const f=db.prepare("select * from dogs where id=? and owner_id=?").get(q.body.fromDog,q.u.id),t=db.prepare("select * from dogs where id=? and owner_id!=?").get(q.body.toDog,q.u.id);
 if(!f||!t)return r.status(400).json({error:"Choose one of your dogs and another owner’s dog"});
 if(db.prepare("select 1 from requests where (from_dog=@a and to_dog=@b) or (from_dog=@b and to_dog=@a)").get({a:f.id,b:t.id}))return r.status(400).json({error:"A request between these dogs already exists"});
 db.prepare("insert into requests(from_dog,to_dog) values(?,?)").run(f.id,t.id);r.json({})});
app.get("/api/requests",need,(q,r)=>{const rows=db.prepare("select r.*,f.owner_id fo,t.owner_id tw from requests r join dogs f on f.id=r.from_dog join dogs t on t.id=r.to_dog where f.owner_id=@u or t.owner_id=@u order by r.id desc").all({u:q.u.id});
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
app.use(express.static(path.join(__dirname,"public")));
app.use((e,q,r,n)=>r.status(400).json({error:e.message}));
app.listen(process.env.PORT||3000,()=>console.log("PawMate running"));
