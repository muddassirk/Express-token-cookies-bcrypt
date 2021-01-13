var express = require("express");
var cors = require("cors");
var morgan = require("morgan");
var bodyParser = require("body-parser");
var mongoose = require("mongoose");
var bcrypt = require("bcrypt-inzi");
var jwt = require("jsonwebtoken");
var cookieParser = require("cookie-parser")
var path = require('path');
const { now } = require("mongoose");
// const { hash } = require("bcrypt-nodejs");

var SERVER_SECRET = process.env.SECRET || "1234";

// let dbURI = "mongodb+srv://legend:legend123@mongodb.xd2iy.mongodb.net/testdb?retryWrites=true&w=majority"
let dbURI = "mongodb+srv://legend:legend123@cluster0.2c3x6.mongodb.net/testdb?retryWrites=true&w=majority"
mongoose.connect(dbURI, { useNewUrlParser: true, useUnifiedTopology: true });

mongoose.connection.on('connected', function () {
    console.log("mongoose is connected")
})

mongoose.connection.on('disconnected', function () {
    console.log("mongoose is disconnected")
    process.exit(1);
})

mongoose.connection.on('error', function (err) {
    console.log("mongoose connection error: ", err)
    process.exit(1)
})

process.on("SIGINT", function () {
    console.log("app is terminating")
    mongoose.connection.close(function () {
        console.log("mongoose default connection is closed")
        process.on(0)
    })
})

var userSchema = new mongoose.Schema({

    "name": String,
    "email": String,
    "password": String,
    "createdOn": { "type": Date, "default": Date.now },
    "activeSince": Date
})

var userModel = new mongoose.model("users", userSchema);

var app = express();
app.use(cors({
    origin: "*",
    credentials: true
}));
app.use(morgan('dev'))
app.use(bodyParser.json())
app.use(cookieParser())



app.post("/signup", (req, res, next) => {
    if (
        !req.body.name ||
        !req.body.email ||
        !req.body.password
    ) {
        res.status(403).send(`
            please send name, email and password
            e.g:
            {
                "name" : "Khan"
                "email" : "Khan@gmail.com"
                "password" : "123"
            }`)
        return;
    }


    userModel.findOne({ email: req.body.email },
        function (err, doc) {
            if (!err && !doc) {
                bcrypt.stringToHash(req.body.password).then(function (hash) {
                    var newUser = new userModel({
                        "name": req.body.name,
                        "email": req.body.email,
                        "password": hash,
                    })

                    newUser.save((err, data) => {
                        if (!err) {
                            res.send({
                                message: "user created"
                            })
                        } else {
                            console.log(err)
                            res.status(500).send({
                                message: "user created error, " + err
                            })
                        }
                    });
                })
            }
            else if (err) {
                res.status(500).send({
                    message: "db error"
                })
            }
            else {
                res.status(409).send({
                    message: "user already exist"
                })
            }
        }
    )
})


app.post("/login", (req, res, next) => {
    if (!req.body.email || !req.body.password) {
        res.status(403).send(`
            please send email and password in json body
            e.g:
            {
                "email" : "khan@gamil.con,
                "password" : "123"
            }`)
        return;
    }



    userModel.findOne({ email: req.body.email },
        function (err, user) {
            if (err) {
                res.status(500).send({
                    message: "an error occured: " + JSON.stringify(err)
                });
            } else if (user) {

                bcrypt.varifyHash(req.body.password, user.password).then(isMatched => {
                    if (isMatched) {
                        console.log("matched");

                        var token =
                            jwt.sign({
                                id: user._id,
                                name: user.name,
                                email: user.email,
                                ip: req.connection.remoteAddress
                            }, SERVER_SECRET)

                        res.cookie('jToken', token, {
                            maxAge: 86_400_000,
                            httpOnly: true
                        })

                        res.send({
                            message: "login success",
                            user: {
                                name: user.name,
                                email: user.email,
                            },
                            token: token
                        });

                    } else {
                        console.log("not matched");
                        res.status(401).send({
                            message: "incorrect password"
                        })
                    }
                }).catch(e => {
                    console.log("error: ", e)
                })

            } else {
                res.status(403).send({
                    message: "user not found"
                });
            }
        });

})


app.use(function (req, res, next) {
    console.log("req.cookies: ", req.cookies);
    if (!req.cookies.jToken) {
        res.status(401).send("include  http only credentials with every request")
        return;
    }
    jwt.verify(req.cookies.jToken, SERVER_SECRET, function (err, decodedData) {
        if (!err) {
            const issueDate = decodedData.iat * 1000;
            const nowDate = new Date().getTime();
            const diff = nowDate - issueDate;// 86,400,000

            if (diff > 300000) { //expire after 5 min (in milisecond)
                res.status(401).send("token expired")
            } else {//issue new token
                var token = jwt.sign({
                    id: decodedData.id,
                    naem: decodedData.name,
                    email: decodedData.email,
                }, SERVER_SECRET)
                res.cookie('jToken', token, {
                    maxAge: 86_400_000,
                    httpOnly: true
                });
                req.body.jToken = decodedData
                next();

            }

        } else {
            res.status(401).send("invalid token")
        }
    });

})

app.get("/profile", function (req, res, next) {

    console.log(req.body)


    userModel.findById(req.body.jToken.id, 'name emai creatOn',
        function (err, doc) {
            if (!err) {
                res.send({
                    profile: doc
                })
            } else {
                res.status(500).send({
                    message: "server error"
                })
            }
        }
    )
})

app.post("/logout", function (req, res, next) {
    res.cookie('jToken', "", {
        maxAge: 86_400_000,
        httpOnly: true

    });
    res.send("logout success");
})


const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
    console.log("server is runnig on: ", PORT);
})