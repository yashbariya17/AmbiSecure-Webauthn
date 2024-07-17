const express = require("express");
const session = require("express-session");
const fetch = require("node-fetch");
const {
  verifyRegistrationResponse,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  generateAuthenticationOptions,
} = require("@simplewebauthn/server");

const memoryStore = require("memorystore");
const { LocalStorage } = require("node-localstorage");

const app = express();
const MemoryStore = memoryStore(session);
const localStorage = new LocalStorage("./db");

app.use(express.json());
app.use(express.static("./public/"));

// Session middleware configuration
app.use(
  session({
    resave: false,
    secret: "secret123",
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      maxAge: 86400000,
    },
    store: new MemoryStore({
      checkPeriod: 86400000,
    }),
  })
);

// CORS configuration to allow requests from your frontend origin
const cors = require('cors');
const rpID = "webauthn-node.onrender.com";
const origin = `https://${rpID}`;
app.use(cors({
  origin: origin,
  credentials: true, // Required for allowing credentials (cookies, sessions) to be sent cross-origin
}));

const port = 3000;
const rpName = "WebAuthn Tutorial";
const expectedOrigin = origin;

// Endpoint for initiating registration
app.post("/register", async (req, res) => {
  try {
    // Fetch user data from your backend
    let userData = await fetch('http://18.215.166.62/register', {
      method: "POST",
      body: JSON.stringify({ username: req.body.username }),
      headers: { "Content-Type": "application/json" }
    });

    if (!userData.ok) {
      throw new Error(`Failed to fetch registration data: ${userData.statusText}`);
    }

    userData = await userData.json();

    // Format user data for registration options
    const formattedData = {
      passKeys: userData.map(data => ({
        counter: data.counter,
        id: data.id,
        backedUp: !!data.backedUp,
        webAuthnUserID: data.webAuthnUserID,
        deviceType: data.deviceType,
        transports: data.transport ? data.transport.split(",") : [],
        credentialPublicKey: data.credentialPublicKey ? data.credentialPublicKey.split(",") : [],
      })),
      username: req.body.username,
    };

    const { username: userName, passKeys } = formattedData;

    // Generate registration options
    const opts = {
      rpID,
      rpName,
      userName,
      attestationType: "none",
      supportedAlgorithmIDs: [-7, -257],
      authenticatorSelection: {
        residentKey: "discouraged",
      },
      excludeCredentials: passKeys?.map((key) => ({
        id: key.id,
        transports: key.transports,
      })),
    };

    const options = await generateRegistrationOptions(opts);

    // Store user data and registration options in session
    req.session.challenge = { user: formattedData, options };
    res.json(options);

  } catch (err) {
    console.error("Error fetching registration data:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Endpoint for completing registration
app.post("/register/complete", async (req, res) => {
  const response = req.body;
  const { options, user } = req.session.challenge;

  const opts = {
    response,
    expectedOrigin,
    expectedRPID: rpID,
    requireUserVerification: false,
    expectedChallenge: options.challenge,
  };

  try {
    // Verify registration response
    const verification = await verifyRegistrationResponse(opts);

    if (verification.verified && verification.registrationInfo) {
      const { counter, credentialID, credentialBackedUp, credentialPublicKey, credentialDeviceType } = verification.registrationInfo;

      console.log("Registration Info:", verification.registrationInfo);

      // Update user data with new registration info
      const passKeyIndex = user.passKeys.findIndex(key => key.id === credentialID);
      if (passKeyIndex === -1) {
        user.passKeys.push({
          counter,
          id: credentialID,
          backedUp: credentialBackedUp,
          webAuthnUserID: options.user.id,
          deviceType: credentialDeviceType,
          transports: response.response.transports,
          credentialPublicKey: Array.from(credentialPublicKey),
        });
      }

      // Store updated user data (assuming you persist this data)
      // Example: await localStorage.setItem(user.username, JSON.stringify(user));

      // Clear session challenge
      req.session.challenge = undefined;
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: "Registration verification failed" });
    }

  } catch (error) {
    console.error("Error verifying registration:", error);
    res.status(400).json({ error: error.message });
  }
});

// Endpoint for initiating login
app.post("/login", async (req, res) => {
  try {
    // Fetch user data for login
    const userData = await fetch('http://18.215.166.62/login', {
      method: "POST",
      body: JSON.stringify({ username: req.body.username }),
      headers: { "Content-Type": "application/json" }
    });

    if (!userData.ok) {
      throw new Error(`Failed to fetch user data: ${userData.statusText}`);
    }

    const user = await userData.json();

    // Check if user and passKeys are available
    if (!user || user.length === 0 || !user.passKeys || user.passKeys.length === 0) {
      return res.status(400).json({ error: "Invalid user or no passkeys found" });
    }

    const opts = {
      rpID,
      allowCredentials: user.passKeys.map(key => ({
        id: key.id,
        transports: key.transports,
      })),
    };

    // Generate authentication options
    const options = await generateAuthenticationOptions(opts);

    // Store user data and authentication options in session
    req.session.challenge = { user, options };
    res.json(options);

  } catch (err) {
    console.error("Error fetching user data:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Endpoint for completing login
app.post("/login/complete", async (req, res) => {
  const { options, user } = req.session.challenge;
  const body = req.body;

  const passKey = user.passKeys.find(key => key.id === body.id);
  if (!passKey) {
    return res.status(400).json({ error: `Could not find passkey ${body.id} for user ${user.id}` });
  }

  const opts = {
    response: body,
    expectedOrigin,
    expectedRPID: rpID,
    authenticator: passKey,
    requireUserVerification: false,
    expectedChallenge: options.challenge,
  };

  try {
    // Verify authentication response
    const verification = await verifyAuthenticationResponse(opts);

    if (verification.verified) {
      passKey.counter = verification.authenticationInfo.newCounter;
      // Update user data with new counter (assuming you persist this data)
      // Example: await localStorage.setItem(user.username, JSON.stringify(user));

      // Clear session challenge
      req.session.challenge = undefined;
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: "Authentication verification failed" });
    }

  } catch (error) {
    console.error("Error verifying authentication:", error);
    res.status(400).json({ error: error.message });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`🚀 Server ready on port ${port}`);
});
