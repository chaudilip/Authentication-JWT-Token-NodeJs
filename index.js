import express from "express";
import path from "path";
const app = express();
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

mongoose.connect("mongodb://localhost:27017",{
    dbName:"backend",
}).then((c) => console.log("Connection established successfully")).catch((err) => console.log(err))

const users = [];

const userSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String
});

const User = mongoose.model("User",userSchema);
//using middleware
app.use(express.static(path.join(path.resolve(),"public")));
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());

app.set('view engine', 'ejs');


const isAuthenticated = async(req,res,next) =>{
    const {token} = req.cookies;
    if(token){
        const decoded = jwt.verify(token,"skdjfjslfj");
        req.user = await User.findById(decoded._id);
        next();
    }
    else{
        res.redirect("login");
    }
}

app.get("/login",(req,res)=>{
    res.render("login");
})

app.get("/logout",(req,res)=>{
    res.cookie("token",null,{
        expires:new Date(Date.now())
    })
    res.redirect("/");
})

app.get("/",isAuthenticated,(req,res)=>{
    console.log(req.user);
    res.render("logout",{name:req.user.name});
})

app.get("/register",(req,res)=>{
    res.render("register");
})

app.post("/register",async(req,res)=>{
    const {name,email,password} = req.body;
    let user = await User.findOne({email});
    if(user){
       return res.redirect("/login");
    }
    //converting plain text password to hash password with 10 salt rounds
    const hashedPassword = await bcrypt.hash(password,10);
    user = await User.create({
        name,
        email,
        password:hashedPassword
    })
    
    const token = jwt.sign({_id:user._id},"skdjfjslfj");
    res.cookie("token",token,{
        httpOnly:true,
        expires: new Date(Date.now() + 1000 * 60)
    });
    res.redirect("/");
});

app.post("/login",async(req,res)=>{
   //destructure the data object 
    const {email,password} = req.body;
    //store the value of form email and password and check if exists in database
    let user = await User.findOne({email});
    //if not then redirect to register
    if(!user) return res.redirect("/register");
    //check if the password match the database password
    const isMatch = await bcrypt.compare(password,user.password);
    //if not  then redirect to login page with message
    if(!isMatch) return res.render("login",{email,message:"Incorrect Password"})
    //if user exists and password is correct then we will make another jwt token
    const token = jwt.sign({_id:user._id},"skdjfjslfj");
    res.cookie("token",token,{
        httpOnly:true,
        expires: new Date(Date.now() + 1000 * 60)
    });
    res.redirect("/");
})

app.listen(5000,()=>{
    console.log('listening on port ' + 5000);
})
