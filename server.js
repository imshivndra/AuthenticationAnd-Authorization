require('dotenv').config();

const express=require('express');
const app=express();
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');

app.use(express.json());

const users=[];
const refreshTokens=[];

app.post('/token',(req,res)=>{
    const refreshToken=req.body.token;
    if(refreshToken==null) return res.status(401).send("null token" );
    if(!refreshTokens.includes(refreshToken)) return res.status(403).send("invalid refresh token");
    jwt.verify(refreshToken,process.env.REFRESH_TOKEN_KEY,(error,user)=>{
        console.log(user);
        if(error) return res.sendStatus(403);
        const accessToken=accessTokenGenerator(user);
        res.json({"accesstoken":accessToken});
    })
});

app.post('/signup',async (req,res)=>{
    try{
        const hashedPassword=await bcrypt.hash(req.body.password,10);
        const user={userName:req.body.userName,
                    password:hashedPassword,
                    dog:req.body.dogName};
         users.push(user);  
         
         res.status(201).send("user created");        
    }catch(e){
        console.log(e);
        res.status(500).send(e);
    }

});

app.post('/login',async (req,res)=>{
    const user=users.find((user)=>user.userName===req.body.userName);
    console.log("From LOgin : ",user);
    if (user==null) res.status(400).send('unable to find');
    try{
        if(await bcrypt.compare(req.body.password,user.password)){
            const ACCESS_TOKEN = await accessTokenGenerator(user);
            const REFRESH_TOKEN=await jwt.sign(user,process.env.REFRESH_TOKEN_KEY);
            refreshTokens.push(REFRESH_TOKEN);
            return res.json({"access token" :ACCESS_TOKEN,"refresh token":REFRESH_TOKEN});
        }
        else{
            return res.send("incorrect password");
        }

    }catch(e){
        console.log(e);
        res.status(500).send("password is incorrect");
    }

});

app.get('/user',authenticateToken,(req,res)=>{
    res.json(users.find((user)=>user.userName===req.body.userName));
})

async function accessTokenGenerator(user){
    return await jwt.sign(user,process.env.ACCESS_SECRET_KEY,{expiresIn:"15s"});
}


function authenticateToken(req,res,next){
    console.log("1st line of auth");
    const authHeader=req.headers['authorization'];
    console.log(authHeader);
    const token=authHeader && authHeader.split(" ")[1];
    if(token==null) return res.status(401);
    jwt.verify(token,process.env.ACCESS_SECRET_KEY,(error,user)=>{
        if(error){
            return res.status(403).send(error);
        }
        
        req.body=user;
        console.log("Authenticate vala request body ",req.body);
        next()

    });
}

 

app.listen(3000,()=>{
    console.log('server is up on port 3000 ! ');
})