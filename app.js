require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = process.env;

const User = require("./model/user");
const auth = require("./middleware/auth");

const app = express();

app.use(express.json({ limit: "50mb" }));

app.post("/register", async (req, res) => {
  try {
    // Get user input
    const { first_name, last_name, phone, password } = req.body;

    // Validate user input
    if (!(phone && password && first_name && last_name)) {
      res.status(400).send("All input is required");
    }

    // check if user already exist
    // Validate if user exist in our database
    const oldUser = await User.findOne({ phone });

    if (oldUser) {
      return res.status(409).send("User Already Exist. Please Login");
    }

    //Encrypt user password
    encryptedPassword = await bcrypt.hash(password, 10);

    // Create user in our database
    const user = await User.create({
      first_name,
      last_name,
      phone: phone.toLowerCase(), // sanitize: convert phone to lowercase
      password: encryptedPassword,
    });

    // Create token
    const token = jwt.sign(
      { user_id: user._id, phone },
      process.env.TOKEN_KEY,
      {
        expiresIn: "2h",
      }
    );
    // save user token
    user.token = token;

    // return new user
    res.status(201).json(user);
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  try {
    // Get user input
    const { phone, password } = req.body;

    // Validate user input
    if (!(phone && password)) {
      res.status(400).send("All input is required");
    }
    // Validate if user exist in our database
    const user = await User.findOne({ phone });

    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, phone },
        process.env.TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );

      // save user token
      user.token = token;

      // user
      res.status(200).json(user);
    }
    res.status(400).send("Invalid Credentials");
  } catch (err) {
    console.log(err);
  }
});

app.get("/address", auth, async (req, res) => {
  const user = await User.findOne({ phone: req.user.phone });
  res.status(200).json({
    success: "true",
    message: "User's addresses",
    data: user.address,
  });
});

app.post("/address", auth, async (req, res) => {
  const user = await User.findOne({ phone: req.user.phone });
  await User.findOneAndUpdate(
    { phone: req.user.phone },
    { $set: { address: user.address.concat(req.body.address) } }
  );
  res.status(200).json({
    success: "true",
    message: "Address Added",
  });
});

app.post("/webhook", async (req, res) => {
  // Retrieve the request's body
  // Validate custom headers
  const profile = req.body.verification_profile;
  const status = profile?.result?.status;

  console.log(req);

  if (!status) {
    // stop
    return res.status(200);
  }

  switch (status) {
    case "in_progress":
      // Then define and call a method to handle the verification in progress status
      // handleVerificationInProgress()
      break;
    case "verified":
      // Then define and call a method to handle the successful verification status
      // handleVerificationSuccessful()
      break;
    case "unverifiable":
      // Then define and call a method to handle the unverifiable verification status
      // handleVerificationFailed()
      break;
    default:
      console.log(`Unhandled event type ${status}`);
  }
  res.status(200).json({
    success: "true",
    message: "Status Updated",
  });
});

// This should be the last route else any after it won't work
app.use("*", (req, res) => {
  res.status(404).json({
    success: "false",
    message: "Page not found",
    error: {
      statusCode: 404,
      message: "You reached a route that is not defined on this server",
    },
  });
});

module.exports = app;
