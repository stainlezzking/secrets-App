const mongoose = require("mongoose")
const  bcrypt  = require("bcrypt")
const GoogleStrategy = require("passport-google-oauth20")
// create schema

//secrets schema
const secretSchema =  {
    secret : String,
    created_at : String,
    author : String
}
// user schema
const userSchema = new mongoose.Schema({
    username : String,
    password : String,
    secrets : [secretSchema]
})


//serialize and desserialize Users
function serializePass(passport,User,localStrategy){
    
passport.serializeUser((user,done)=>{
    done(null,user.id)
})

passport.deserializeUser((id,done)=>{
    User.findById(id)
    .then(user=>{
        if(user){
           return done(null,user)
        }
    })
})

passport.use(
    new localStrategy(function(username, password, done) {
       User.findOne({ username: username }, function(err, user) {
           if (user) {
            bcrypt.compare(password, user.password, function(err,result){
                if(result){
                    return done(null, user)    
                }else{
                    return done(null,false)
                }
            })
                 // if(!user)
           }else{
               return done(null,false)
           }


       });
   })
);


}


function googleConfig(passport,User) {
  
    passport.use(new GoogleStrategy({
        clientID: process.env.client_Id ,
        clientSecret: process.env.client_Secret,
        callbackURL: "http://localhost:2000/auth/google/callback"
      },
      function(accessToken, refreshToken, profile, done) {
       User.findOne({username:profile._json.email}, function(err,user){
           if(err) console.log(err.message)
           if (user){
               return done(null, user)
           }
           if(!user){
               User.create({
                   username : profile._json.email,
               }).then(newuser=> done(null,newuser))
           }
       })
        console.log(profile._json)
      }
    ));
}
module.exports ={
    serializePass,
    userSchema,
    googleConfig
}