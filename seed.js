// Loads 20 demo dogs (and 15 demo owners) into your PawMate database.
// Add:     node --env-file-if-exists=.env seed.js
// Remove:  node --env-file-if-exists=.env seed.js --remove
const{DatabaseSync}=require("node:sqlite"),bcrypt=require("bcryptjs"),crypto=require("crypto"),path=require("path"),fs=require("fs");
if(process.env.NODE_ENV==="production"){console.error("Refusing to add demo data when NODE_ENV=production.");process.exit(1)}
const DATA=process.env.DATA_DIR||path.join(__dirname,"data"),file=path.join(DATA,"pawmate.db");
if(!fs.existsSync(file)){console.error("No database found. Run `npm start` once, stop it with Ctrl+C, then run this again.");process.exit(1)}
const db=new DatabaseSync(file);db.exec("pragma foreign_keys=ON");
const DOM="@demo.pawmate.test";
db.prepare("delete from users where email like ?").run("%"+DOM); // removes earlier demo data, including their dogs
if(process.argv.includes("--remove")){console.log("Demo data removed.");process.exit(0)}
const PASS=process.env.DEMO_PASSWORD||"demo12345",hash=bcrypt.hashSync(PASS,10);
const owners=["Anindita Roy","Sourav Das","Priya Mukherjee","Imran Khan","Rahul Sen","Neha Bose","Arjun Ghosh","Mitali Paul","Debojit Saha","Ritika Sharma","Subho Dutta","Tania Chatterjee","Kaushik Mondal","Farhana Ali","Amit Banerjee"];
const DOCS=["Vaccination certificate","Vet health check","Pedigree papers"];
// owner, name, breed, sex, age, city, temperament, health, vaccination, pedigree, approved documents (0 to 3)
const dogs=[
[0,"Bruno","Labrador Retriever","Male","3 years","Kolkata","Calm, great with kids","Hips and elbows clear (2025)","Up to date, Oct 2026","KCI/LR/2023/0481",3],
[1,"Mishti","Labrador Retriever","Female","2 years","Kolkata","Playful, high energy","Eye test clear","Up to date, Sep 2026","KCI/LR/2024/1120",2],
[2,"Coco","Golden Retriever","Female","4 years","Howrah","Gentle, well trained","Hips clear, one earlier litter","Up to date, Oct 2026","KCI/GR/2022/0977",3],
[3,"Simba","Golden Retriever","Male","3 years","Kolkata","Friendly, loves water","Hips and heart clear","Up to date, Nov 2026","KCI/GR/2023/0640",3],
[3,"Zeus","German Shepherd","Male","3 years","Salt Lake, Kolkata","Alert, obedient","Hips B-stamp","Up to date, Aug 2026","KCI/GS/2023/0302",1],
[4,"Rani","German Shepherd","Female","2 years","Barrackpore","Confident, well trained","Hips A-stamp","Up to date, Oct 2026","KCI/GS/2024/0518",2],
[4,"Tuktuk","Beagle","Male","2 years","Barasat","Curious, friendly","Not yet tested","Due in December","",0],
[5,"Daisy","Beagle","Female","3 years","Kolkata","Sweet, a little vocal","Eyes clear","Up to date, Sep 2026","KCI/BG/2023/0211",2],
[5,"Luna","Shih Tzu","Female","3 years","Kolkata","Affectionate, calm","Heart and eyes clear","Up to date, Oct 2026","KCI/ST/2023/0655",2],
[6,"Bholu","Shih Tzu","Male","4 years","Howrah","Playful, cuddly","Dental check done","Up to date, Jul 2026","KCI/ST/2022/0390",1],
[7,"Max","Pug","Male","2 years","Kolkata","Funny, social","Breathing assessed, fine","Up to date, Oct 2026","KCI/PG/2024/0072",2],
[7,"Lola","Pug","Female","3 years","Dum Dum","Calm, loves naps","Eye test clear","Up to date, Sep 2026","KCI/PG/2023/0150",0],
[8,"Thor","Rottweiler","Male","3 years","Siliguri","Steady, protective, socialised","Hips and elbows clear","Up to date, Aug 2026","KCI/RW/2023/0098",3],
[9,"Roxy","Rottweiler","Female","2 years","Siliguri","Confident, good with family","Hips clear","Up to date, Oct 2026","KCI/RW/2024/0133",2],
[10,"Teddy","Pomeranian","Male","2 years","Kolkata","Lively, bold","Knees checked, fine","Up to date, Nov 2026","KCI/PM/2024/0301",2],
[10,"Snow","Pomeranian","Female","3 years","Kolkata","Gentle, loves attention","Healthy, vet checked","Up to date, Oct 2026","",1],
[11,"Cooper","Cocker Spaniel","Male","4 years","Kolkata","Cheerful, easy to train","Ears and eyes clear","Up to date, Jun 2026","KCI/CS/2022/0187",2],
[12,"Bella","Cocker Spaniel","Female","3 years","Asansol","Sweet, energetic","Eyes clear","Up to date, Sep 2026","KCI/CS/2023/0244",1],
[13,"Raja","Rajapalayam","Male","3 years","Durgapur","Loyal, reserved with strangers","Healthy, vet checked","Up to date, Aug 2026","Club registration RP/0412",2],
[14,"Rani Devi","Rajapalayam","Female","2 years","Durgapur","Alert, affectionate at home","Healthy, vet checked","Up to date, Oct 2026","Club registration RP/0519",1]];
// a few profiles share more or less than the default, so privacy settings can be tried out
const vis={4:{health:"public"},6:{contact:"private"},11:{city:"matches"},15:{pedigree:"public"},19:{temperament:"matches"}};
const DEF={breed:"public",sex:"public",age:"public",city:"public",temperament:"public",health:"matches",vaccination:"public",pedigree:"matches",contact:"matches",address:"private",photo:"public"};
const uid=owners.map((n,i)=>db.prepare("insert into users(email,name,pass) values(?,?,?)").run(`demo${i+1}${DOM}`,n,hash).lastInsertRowid);
dogs.forEach((d,i)=>{const[o,name,breed,sex,age,city,temperament,health,vaccination,pedigree,n]=d,id=crypto.randomUUID();
 db.prepare("insert into dogs(id,owner_id,name,vis,breed,sex,age,city,temperament,health,vaccination,pedigree,contact,address) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
  .run(id,uid[o],name,JSON.stringify({...DEF,...vis[i]}),breed,sex,age,city,temperament,health,vaccination,pedigree,`+91 90000 ${10001+i}`,`Demo address ${i+1}, ${city}`);
 DOCS.slice(0,n).forEach(t=>db.prepare("insert into docs(dog_id,type,file,orig,status) values(?,?,?,?,'approved')").run(id,t,"demo.pdf",t+".pdf"))});
console.log(`Added ${dogs.length} demo dogs and ${owners.length} demo owners.`);
console.log(`Demo owners log in on the normal page as demo1${DOM} to demo15${DOM} with password: ${PASS}`);
console.log("Remove them before going live: node --env-file-if-exists=.env seed.js --remove");
