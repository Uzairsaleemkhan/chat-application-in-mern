const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs')
const express = require('express');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser')
const mongoose = require('mongoose')
const cors = require('cors')
const app = express()
const ws = require('ws')
const User = require('./models/User')
 dotenv.config()
  mongoose.connect(process.env.MONGODB_CONNECTION_STRING).then(conn=>{
    console.log('mongodb connected on connection '+ conn.connection.host)
  }).catch(err=>{
    console.log('error connecting to mongo' +err)
  })
const jwtSecret = process.env.JWT_SECRET;
const bcryptSalt = bcrypt.genSaltSync(10)
app.use(
    cors({
        credentials:true,
        origin:'http://localhost:5173'
    })
    )
    app.use(cookieParser())
    app.use(express.json())


    app.get('/profile',(req,res)=>{
        const token = req.cookies?.token;
        if(token){

            jwt.verify(token,jwtSecret,{},(err,userData)=>{
                if(err) throw err
                res.json(userData)
            })
        }
        else{
            res.status(401).json('no token')
        }
    })
app.get('/test',(req,res)=>{

    res.send('Hello just testing')
})

app.post('/login',async (req,res)=>{
    const{username,password} = req.body;
try{

    const foundUser = await User.findOne({username})
    if(foundUser){
        const passOk = bcrypt.compare(password,foundUser.password)
        if(passOk){
            jwt.sign({userId:foundUser._id,username},jwtSecret,{},(err,token)=>{
                if(err) throw err
                res.cookie('token',token,{sameSite:'none',secure:true}).status(200).json({userId:foundUser._id})
            })
        }

    }

}

catch(error){
    res.status(401).json({error:'user not found'})
}

})

app.post('/register',async (req,res)=>{
const{username,password} =req.body;
const hashedPassword = bcrypt.hashSync(password,bcryptSalt)
try{

    const response = await User.create({
        username,password:hashedPassword
    })
    jwt.sign({userId:response._id,username},jwtSecret,{},(err,token)=>{
        if(err){
            throw err
        }
        res.cookie('token',token,{sameSite:'none',secure:true}).status(201).json({userId:response._id})
    })
}
    catch(error){
        throw error
    }
})

  const server= app.listen(4040,()=>{
    console.log('app listening on port 4040')
})

const wss =   new ws.WebSocketServer({server})

    wss.on('connection',(connection,req)=>{

        console.log('connected')

        const cookies = req.headers.cookie;
        if(cookies){
         const tokenCookieString =   cookies.split(';').find((str)=>(str.startsWith('token=')))
        

         if(tokenCookieString){
           const token = tokenCookieString.split('=')[1]
           if(token){
               console.log(token)
               jwt.verify(token,jwtSecret,{},(err,data)=>{
                if(err) throw err
                const {username, userId} =data
                connection.username = username;
                connection.userId = userId
               })
            }

         }

        }

        [...wss.clients].forEach((client)=>{

            client.send( 
                JSON.stringify({
                    online:[...wss.clients].map((c)=>({userId:c.userId,username:c.username}))
                })
            )
        })


    })
