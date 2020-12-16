"use strict"

const express = require("express")
const app = express()
const mongoose = require("mongoose")
const bodyParser = require("body-parser")
const passport = require("passport")
const localStrategy = require("passport-local")
const session = require("express-session")
const middleware = require(__dirname +"/modules/middleware")
// const { allSecrets } = require(__dirname +"/modules/middleware")
const secretKey = require(__dirname + "/modules/secret.js")
const allPass = require("./modules/pass-setup")
const { userSchema, googleConfig } = require("./modules/pass-setup")
const bcrypt = require("bcrypt")




app.use(express.static("public"))
app.use(bodyParser.urlencoded({extended:false}))

app.use(session({
   // secret : process.env.session_key,
    secret :secretKey.session_key,
    resave : false,
    saveUninitialized : false,
    maxAge : 20 * 24 * 60 * 60 
}))

app.set("view engine", "ejs")

app.use(passport.initialize())
app.use(passport.session())

// connection to mongoose
mongoose.connect("mongodb://localhost:27017/MyDB",{ useNewUrlParser: true,useUnifiedTopology: true })
//mongoose.connect("mongodb+srv://"+process.env.db_username+":"+ process.env.db_password+"@todotest.pephm.mongodb.net/secrets?retryWrites=true&w=majority",{ useNewUrlParser: true,useUnifiedTopology: true })


//create model/collection
const User = new mongoose.model("user", userSchema)

// authenticate with google, raw code in pass-setup file
googleConfig(passport,User)

//serialize users
allPass.serializePass(passport,User,localStrategy)


app.get("/", (req,res)=>{
    res.render("home")
})

app.route("/register")
.get((req,res)=>{
    res.render("register")
})
.post((req,res)=>{
    if(req.body.username.trim() && req.body.password.trim()){
        User.findOne({username : req.body.username},function(err,user){
            if(err) console.log(err.message)
            console.log(user)
            if(user){
                passport.authenticate("local")(req,res,function(){
                    res.redirect("/profile")
                })
            }
            if(!user){
                // hashing with bcrypt
                //bcrypt.hash(req.body.password, process.env.bcrypt_saltRounds, function(err, hash){
                bcrypt.hash(req.body.password, secretKey.bcrypt_saltRounds, function(err, hash){
                    User.create({
                    username : req.body.username,
                    password : hash
                })
                .then(data=>{
                    console.log("data saved :" + data)
                    passport.authenticate("local")(req,res,function(){
                        res.redirect("/profile")
                    })
                })
                })

            }
        })

}
})


app.route("/login")
.get( (req,res)=>{
    res.render("login")
})
.post(passport.authenticate("local"),(req,res)=>{
    res.redirect("/profile")
})

app.get("/profile",middleware.status, (req,res)=>{
    res.render("profile", {user:req.user, hidden:false})
})

app.get("/profile/:user", function(req,res){
    User.findOne({username : req.params.user}, function(err,user){
        if(err) console.log(err.message)
        if(user){
           if(req.user){
               // if the user is loggded in 
            if(user.id === req.user.id){
                // redirect if the URL matches the user
                res.redirect("/profile")
            }else{
                // if user is logged in but viewing another profile
                res.render("profile",{user, hidden : true})
            }
           }else{
               //  if the visitor is not a user
            res.render("profile",{user, hidden : true})
        }
        }else{
            // if no user was found
            res.send(404,"cannot find your page")
        }
    })
})

app.get("/submit",middleware.status,function(req,res){
      res.render("submit")   
})
app.post("/submit", function(req,res){

    const newSecret = {
        secret : req.body.secret,
        created_at : new Date().toDateString(),
        author : req.user.username
    }
    console.log(newSecret)
    User.updateOne({_id:req.user.id}, {$push : {secrets : newSecret}}, function(err,data){
       res.redirect("/profile")
    })
})

// GOOGLE AUTHENTUCATION
app.get("/auth/google", passport.authenticate("google", {
    scope : ["profile","email", "openid"]
})
)

app.get("/auth/google/callback", passport.authenticate("google"), function(req,res){
    res.redirect("/profile")
})


// I WNATED TO ADD PROPERTY TO THE REQUEST OBJ TO BE ACCESSED BY THE NEXT MIDDLE WARE (DIDNT WORK)
// const allSecrets = (req,res,User,next)=>{
//     User.find({"secrets.1" : {$exists : true}}, function(err,data){
//         req.allSecrets = data;
//         next()
//     })
//  }
app.get("/secrets", function(req,res){
    User.find({"secrets.0" : {$exists : true}}, function(err,data){
        if(err) res.send(err)
       res.render("secrets",{ users:data, user : req.user})
    })

})
app.get("/logout", function(req,res){
    req.logout()
    res.redirect("/")
})
app.listen(process.env.PORT || 2000,()=>{
    console.log("sever up on port 3000")
})

