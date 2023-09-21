const express = require("express");

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(express.json());

const SignedInUser = {};

//Welcome endpoint

app.get("/", (req, res) => {
  res.status(200).send("Working Fine");
});

//Users

app.get("/users", (req, res) => {
  res.json(SignedInUser).status(200);
});

//SignIn Endpoint   returns -> username,hashdpassword,jwt token,message

app.post("/SignIn", async (req, res) => {
  try {
    const user = req.body.username;
    const pass = req.body.password;
    const SecretPrivateKey = process.env.SECRET_KEY;
    const Password = await bcrypt.hash(pass, 10);

    const token = await new Promise((resolve, reject) => {
      jwt.sign(user, SecretPrivateKey, (err, token) => {
        if (err) {
          reject(err);
        } else {
          resolve(token);
        }
      });
    });

    const obj = {
      user,
      HashedPassword: Password,
      JWT_Token: token,
      message: "Successfully Signed In :) ",
    };

    SignedInUser[user] = obj; // Storing users credential
    // console.log(SignedInUser)

    res.json(obj).status(200);
  } catch (err) {
    console.log(err);
  }
});

//Middleware to verify user

async function VerifyUSer(req, res, next) {
  const LoggerName = req.body.username;
  const LoggerPAssword = req.body.password;

  let user = SignedInUser[LoggerName];
  if (user && (await bcrypt.compare(LoggerPAssword, user.HashedPassword))) {
    next();
  } else {
    res.status(401).send("Check your credentials ");
  }
}

// login Endpoint -> check password allow to log

app.post("/login", VerifyUSer, (req, res) => {
  res.send(`Successfully Logged in ${req.body.username}`).status(200);
});

// Endpoint to verify Username return username after decoding from token

app.post("/verifyuser", (req, res) => {
  const token = req.body.token;
  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) {
      console.log(err);
    } else {
      res.json({ user: decoded }).status(200);
    }
  });
});

app.listen(4000, () => {
  console.log(" Listening at port 4000 ... ");
});
