const { Collection } = require("mongoose")

const checkLoggedIn = (req,res,next) =>{
        if(req.user){
            next()
        }else{
            res.redirect("/login")
        }
}


module.exports = {
    status : checkLoggedIn,
   
}
