const mongoose = require("mongoose")
const  bcrypt  = require("bcrypt")
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

module.exports ={
    serializePass,
    userSchema
}