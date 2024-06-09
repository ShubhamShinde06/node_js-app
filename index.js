import express from 'express';
import path, { resolve } from 'path';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import jwt from "jsonwebtoken";
import bcrypt from 'bcrypt';
import { hasSubscribers } from 'diagnostics_channel';

const app = express();

// Connection for database
mongoose.connect("mongodb://localhost:27017",{
    dbName : "backend",
})
.then(() => {
    console.log("Database connected");
})
.catch((err) => {
    console.log(err);
})
const userSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String,
});
const User = mongoose.model("User",userSchema)

// using middleware
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser());

// setting up vies Engine
app.set("view engine", "ejs")

const isAuthenricated = async (req,res,next) => {
    const {token} = req.cookies;
    if(token){
       const decode =  jwt.verify(token,"fghgfhsdgfgf");
        req.user = await User.findById(decode._id)
        next();
    } else {
        res.redirect("/login");
    } 
}

app.get("/", isAuthenricated, (req,res)=> {
    res.render("logout",{name:req.user.name})
})

app.get("/register", (req,res)=> {
    res.render("register");
})

app.get("/login", (req,res) => {
    res.render("login");
})

app.get("/logout",(req,res)=> {
    res.cookie("token",null,{
        httpOnly:true,
        expires:new Date(Date.now()),
    });
    res.redirect("/")
})

app.post("/register", async (req,res)=> {
    const {name,email,password} = req.body;


    let user = await User.findOne({email});
    if(user){
        return res.redirect("/login");
    }

    const hsspassword = await bcrypt.hash(password,10);

    user = await User.create({
        name,
        email,
        password: hsspassword,
    });

    const token = jwt.sign({_id: user._id},"fghgfhsdgfgf")
    res.cookie("token", token ,{
        httpOnly:true,
        expires:new Date(Date.now()+ 60 * 1000)
    });
    res.redirect("/")
})

app.post("/login", async (req,res) => {

    const {email,password} = req.body;

    let user = await User.findOne({email});
    if(!user){
        return res.redirect("/register");
    }

    const isMatch = await bcrypt.compare(password,user.password);

    if(!isMatch){
        return res.render("login", { email,message:"inccorect password"})
    }

    const token = jwt.sign({_id: user._id},"fghgfhsdgfgf")
    res.cookie("token", token ,{
        httpOnly:true,
        expires:new Date(Date.now()+ 60 * 1000)
    });
    res.redirect("/")

})

app.listen(5000, ()=> {
    console.log("server is working");
})