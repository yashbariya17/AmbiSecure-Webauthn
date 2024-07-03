const express = require("express")
const session = require("express-session")
const mariadb = require("mariadb")

const pool = mariadb.createPool({
  host: "127.0.0.1",
  user: "root",
  password: "ciright",
  database: "webtuhn",
  connectionLimit: 5,
})

const {
  verifyRegistrationResponse,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  generateAuthenticationOptions,
} = require("@simplewebauthn/server")

const memoryStore = require("memorystore")
const { LocalStorage } = require("node-localstorage")

const app = express()
const MemoryStore = memoryStore(session)
const localStorage = new LocalStorage("./db")

app.use(express.json())
app.use(express.static("./public/"))
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
      checkPeriod: 86_400_000,
    }),
  })
)

const port = 3000
const rpID = "localhost"
const origin = `http://${rpID}`
const rpName = "WebAuthn Tutorial"
const expectedOrigin = `${origin}:${port}`


app.get('/listen',(req,res)=>{
  res.send('Helllo...');
})

app.post("/register", async (req, res) => {
  // console.log("Register request received:", req.body)
  let conn, user
  try {
    conn = await pool.getConnection()

    const userQuery = `
    SELECT * from users  where username = ? ;
  `
    const userData = await conn.query(userQuery, [req.body.username])
    if (userData.length > 0) {
      const formattedData = {
        passKeys: [
          {
            counter: userData[0].counter,
            id: userData[0].id,
            backedUp: !(!userData[0].backedUp),
            webAuthnUserID: userData[0].webAuthnUserID,
            deviceType: userData[0].deviceType,
            transports: userData[0].transport
            ? userData[0].transport.split(",")
            : [],
            credentialPublicKey: userData[0].credentialPublicKey
            ? userData[0].credentialPublicKey.split(",")
            : [],
          },
        ],
        username: userData[0].username,
      }
      user = formattedData
    } else {
      user = {
        passKeys: [],
        username: req.body.username,
      }
    }
  } catch (err) {
    if (conn) await conn.rollback()
    console.error("Error inserting data:", err)
  } finally {
    if (conn) conn.release()
  }

  const uname = req.body.username

  const { username: userName, passKeys } = user

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
  }
  const options = await generateRegistrationOptions(opts)

  req.session.challenge = { user, options }
  res.send(options)
})

app.post("/register/complete", async (req, res) => {
  // console.log("Register complete request received:", req.body)

  const response = req.body
  const { options, user } = req.session.challenge
  // console.log('\t\t\theloooooo', user.passKeys)

  const opts = {
    response,
    expectedOrigin,
    expectedRPID: rpID,
    requireUserVerification: false,
    expectedChallenge: options.challenge,
  }

  let verification
  try {
    verification = await verifyRegistrationResponse(opts)
  } catch (error) {
    console.error(error)
    return res.status(400).send({ error: error.message })
  }

  const { verified, registrationInfo } = verification

  if (verified && registrationInfo) {
    const {
      counter,
      credentialID,
      credentialBackedUp,
      credentialPublicKey,
      credentialDeviceType,
    } = registrationInfo

    console.log("Registration Info:", registrationInfo)

    const passKey = user.passKeys.find((key) => key.id === credentialID)

    if (!passKey || passKey.length === 0) {
      user.passKeys.push({
        counter,
        id: credentialID,
        backedUp: credentialBackedUp,
        webAuthnUserID: options.user.id,
        deviceType: credentialDeviceType,
        transports: response.response.transports,
        credentialPublicKey: Array.from(credentialPublicKey),
      })
    }

    try {
      conn = await pool.getConnection()

      // Start a transaction
      await conn.beginTransaction()

     

      const insertQuery = `insert  into users (username,counter,id,backedUp,webAuthnUserID ,deviceType,transports, credentialPublicKey ) 
values (?,?,?,?,?,?,?,?);`

      const passKeys = user.passKeys[0] // Assuming only one passKey per user
      const query = await conn.query(insertQuery, [
        user.username,
        passKeys.counter,
        passKeys.id,
        passKeys.backedUp,
        passKeys.webAuthnUserID,
        passKeys.deviceType,
        `[${passKeys.transports}]`, `[${passKeys.credentialPublicKey}]`
      ])

      // let userId
      // if (userResult == null || userResult?.length === 0) {
      //   const insertUserQuery = "INSERT INTO Users (username) VALUES (?)"
      //   const userInsertResult = await conn.query(insertUserQuery, [
      //     user.username,
      //   ])
      //   userId = userInsertResult.insertId
      // } else {
      //   userId = userResult[0].id
      // }

      // Insert passKeys data
      // const insertPassKeysQuery = `
      //   INSERT INTO passKeys (user_id, counter, backedUp, webAuthnUserID, deviceType)
      //   VALUES (?, ?, ?, ?, ?)
      // `
      // console.log('ssssssssssssssssssssssssssssssssssssssssss\n', `(${typeof (passKeys.credentialPublicKey)})`)
      // const passKeysInsertResult = await conn.query(insertPassKeysQuery, [
      //   userId,
      //   passKeys.counter,
      //   passKeys.backedUp,
      //   passKeys.webAuthnUserID,
      //   passKeys.deviceType,
      //   // Assuming credentialPublicKey is an array
      // ])
      // const passKeyId = passKeysInsertResult.insertId

      // Insert transports
      // if (passKeys.transports && passKeys.transports.length > 0) {
      //   const transportValues = passKeys.transports.map((transport) => [
      //     passKeyId,
      //     transport,
      //   ])
      //   const insertTransportsQuery =
      //     "INSERT INTO Transports (passKey_id, transport) VALUES ?"
      //   await conn.query(insertTransportsQuery, [transportValues])
      // }

      // Insert credential public keys
      // if (
      //   passKeys.credentialPublicKey &&
      //   passKeys.credentialPublicKey.length > 0
      // ) {
      //   const credentialPublicKeyValues = passKeys.credentialPublicKey.map(
      //     (key) => [passKeyId, key]
      //   )
      //   console.log(credentialPublicKeyValues)
      //   const insertCredentialPublicKeysQuery =
      //     "INSERT INTO CredentialPublicKeys (passKey_id, credentialPublicKey) VALUES (?,?,?)"
      //   await conn.query(insertCredentialPublicKeysQuery, [
      //     null,
      //     userId,
      //     `[${passKeys.credentialPublicKey}]`
      //   ])
      // }

      // Commit the transaction
      await conn.commit()
      console.log("Data inserted successfully.")
    } catch (err) {
      // Rollback transaction on error
      if (conn) await conn.rollback()
      console.error("Error inserting data:", err)
    } finally {
      if (conn) conn.release()
    }
    // localStorage.setItem(user.username, JSON.stringify(user))
  }

  req.session.challenge = undefined
  res.send({ verified })
})

app.post("/login", async (req, res) => {
  console.log("Login request received:", req.body)
  let user,conn
  try {
    conn = await pool.getConnection()

    const userQuery = `
    SELECT * from users  where username = ? ;
  `
  console.log('ssssssssssssssssssssssssssssssssssssss\n\\n')
    const userData = await conn.query(userQuery, [req.body.username])
    if (userData.length > 0) {
      const formattedData = {
        passKeys: [
          {
            counter: userData[0].counter,
            id: userData[0].id,
            backedUp: !(!userData[0].backedUp),
            webAuthnUserID: userData[0].webAuthnUserID,
            deviceType: userData[0].deviceType,
            transports: userData[0].transport
            ? userData[0].transport.split(",")
            : [],
            credentialPublicKey: userData[0].credentialPublicKey
            ? JSON.parse( userData[0].credentialPublicKey)
            : [],
          },
        ],
        username: userData[0].username,
      }
      user = formattedData
    }
  
  } catch (err) {
    if (conn) await conn.rollback()
    console.error("Error fetching data:", err)
  } finally {
    if (conn) conn.release()
  }

  const opts = {
    rpID,
    allowCredentials: user?.passKeys.map((key) => ({
      id: key.id,
      transports: key.transports,
    })),
  }
  const options = await generateAuthenticationOptions(opts)

  req.session.challenge = { user, options }
  res.send(options)
})

app.post("/login/complete", async (req, res) => {
  console.log("Login complete request received:", req.body)

  const { options, user } = req.session.challenge
  const body = req.body

  const passKey = user.passKeys.find((key) => key.id === body.id)
  if (!passKey) {
    return res
      .status(400)
      .send({ error: `Could not find passkey ${body.id} for user ${user.id}` })
  }

  console.log("PassKey Info:", passKey)

  const opts = {
    response: body,
    expectedOrigin,
    expectedRPID: rpID,
    authenticator: passKey,
    requireUserVerification: false,
    expectedChallenge: options.challenge,
  }

  let verification
  try {
    verification = await verifyAuthenticationResponse(opts)
  } catch (error) {
    console.error(error)
    return res.status(400).send({ error: error.message })
  }

  const { verified, authenticationInfo } = verification

  if (verified) {
    passKey.counter = authenticationInfo.newCounter
    user.passKeys = user.passKeys.map((i) => (i.id == passKey.id ? passKey : i))
    
    // try {
    //   conn = await pool.getConnection()

    //   // Start a transaction
    //   await conn.beginTransaction()

    //   // Insert user if not exists (assuming username is unique)
     
    //   const insertQuery = `insert  into users (username,counter,id,backedUp,webAuthnUserID ,deviceType,transports, credentialPublicKey ) 
    //   values (?,?,?,?,?,?,?,?);`
      
    //         const passKeys = user.passKeys[0] // Assuming only one passKey per user
    //         const query = await conn.query(insertQuery, [
    //           user.username,
    //           passKeys.counter,
    //           passKeys.id,
    //           passKeys.backedUp,
    //           passKeys.webAuthnUserID,
    //           passKeys.deviceType,
    //           `[${passKeys.transports}]`, `[${passKeys.credentialPublicKey}]`
    //         ])

    //   // Commit the transaction
    //   await conn.commit()
    //   console.log("Data inserted successfully.")
    // } catch (err) {
      
    //   if (conn) await conn.rollback()
    //   console.error("Error inserting data:", err)
    // } finally {
    //   if (conn) conn.release()
    // }
    console.log('\n\n\n',user)
    // localStorage.setItem(user.username, JSON.stringify(user))
  }

  req.session.challenge = undefined
  res.send({ verified })
})

app.listen(port, () => {
  console.log(`🚀 Server ready on port ${port}`)
})
