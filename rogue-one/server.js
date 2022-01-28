const crypto = require("crypto");
const { Buffer } = require("buffer");
const fs = require("fs");

const mysql = require("mysql2");

const express = require("express");
const morgan = require("morgan");

const helmet = require("helmet");
const { nanoid } = require("nanoid");

const jwt = require("jsonwebtoken");

const pkg = require("./package.json");

const APP_SECRET = crypto.randomBytes(128).toString("hex");

const {
  MYSQL_DATABASE = "test",
  MYSQL_USER = "user",
  MYSQL_PASSWORD = "",
  MYSQL_HOST = "db",
  MYSQL_PORT = 3306,
} = process.env;

/**
 * @function createXsrfToken
 * @return a pseudo-random cryptographically strong XSRF token
 */
function createXsrfToken() {
  return crypto.randomBytes(128).toString("hex");
}

/**
 * @function createSession
 * @param {Object}
 *  @property id the ID of the authenticated account
 * @return {Object}
 *  @property token the generated session token
 *  @property xsrf the generated XSRF token
 *  @property expiresIn the expiration delay in seconds from now
 *
 * @description
 *  This function creates a new stateless session in a JWT from a given Account
 *  ID (subject). It generates a XSRF token and defines itself as valid during
 *  1 hour.
 */
function createSession({ id }) {
  const xsrf = createXsrfToken();
  const expiresIn = 3600;
  const subject = id;

  const token = jwt.sign({ xsrf }, APP_SECRET, { expiresIn, subject });

  return { token, xsrf, expiresIn };
}

/**
 * @function validateSession
 * @param {Object}
 *  @property token the stateless session token to verify
 *  @property xsrf the XSRF token to check against session
 * @return Boolean
 *
 * @description
 *  This function checks the validity of a given session token AND a given
 *  XSRF token. XSRF token should be validated against stateless session token.
 */
function validateSession({ token, xsrf }) {
  return true;
}

/**
 * @function getPasswordHash
 * @description
 *  This function generates a hash of a given password
 * @param password [String] the password to be hashed
 * @return [String] the generated password hash
 */
function getPasswordHash(password) {
  const hash = crypto.createHash("sha1");
  hash.update(password);
  return hash.digest("hex");
}

/**
 * @async
 * @function __validateAccountCredentials
 * @description
 *  This function validates an account credentials using a mysql based challenge
 * @param {Object}
 *  @property username  account username
 *  @property password  account password
 * @return {Object} | null  The account object as stored in database if credentials
 *  are validated, null otherwise.
 *
 */
async function __validateAccountCredentials({ username, password }) {
  const db = this.get("db");
  const encryptedPassword = getPasswordHash(password);
  const q = `SELECT * FROM users WHERE username="${username}" AND password="${encryptedPassword}"`;
  const [rows, fields] = await db.promise().query(q);

  return rows.length ? rows[0] : null;
}

/**
 * @async
 * @function __createAccount
 * @description
 *  This function creates a new account, given all account properties to be
 *  stored in database
 * @param {Object}
 *  @property username  account username
 *  @property password  account password
 * @return {Object} the newly created account, null on any insertion error
 *  @property id  account ID
 *  @property username account username
 *  @property password account password
 */
async function __createAccount({ username, password }) {
  const db = this.get("db");
  const encryptedPassword = getPasswordHash(password);
  const id = nanoid();
  const q = `INSERT INTO users (id, username, password) VALUES ("${id}", "${username}", "${encryptedPassword}")`;
  const [rs, _] = await db.promise().query(q);

  return rs.affectedRows ? { id, username, password } : null;
}

/**
 * @async
 * @function __getAccount
 * @description
 *  This function fetches an account given its ID
 * @return {Object} Account object as retrieved from database, or null
 */
async function __getAccount(id) {
  const db = this.get("db");
  const q = `SELECT * FROM users WHERE id="${id}"`;
  const [rows, _] = await db.promise().query(q);
  return rows.length ? rows[0] : null;
}

/**
 * @async
 * @function __getAccounts
 * @description
 *  This function fetches all accounts from database
 * @return {Array<Object>} - an array containing all accounts
 */
async function __getAccounts() {
  const db = this.get("db");
  const q = `SELECT * FROM users`;
  const [rows, _] = await db.promise().query(q);
  return rows;
}

/**
 * @async
 * @function __deleteAccount
 * @description
 *  This function deletes an account, given its ID
 * @param id {Integer}
 * @return Boolean
 */
async function __deleteAccount(id) {
  const db = this.get("db");
  const q = `DELETE FROM users WHERE id="${id}"`;
  const [rs, _] = await db.promise().query(q);
  return rs.affectedRows > 0;
}

/**
 * @async
 * @function __updateAccount
 * @description
 *  This function updates an account, given its properties
 * @param {Object}
 *  @property {String} id account ID
 *  @property {String} username account username
 *  @property {String} password account password
 * @return Boolean
 */
async function __updateAccount({ id, username, password }) {
  const db = this.get("db");
  const encryptedPassword = getPasswordHash(password);
  const q = `UPDATE users SET id="${id}", username="${username}", password="${encryptedPassword}" WHERE id="${id}"`;
  const [rs, _] = await db.promise().query(q);
  return rs.affectedRows > 0;
}

/**
 * @function createApplication
 * @description
 *  This function creates and configures express application
 * @return {Application}
 */
function createApplication() {
  // Setup application
  const app = express();

  // Setup custom methods
  app.set("validateAccountCredentials", __validateAccountCredentials.bind(app));
  app.set("createAccount", __createAccount.bind(app));
  app.set("getAccount", __getAccount.bind(app));
  app.set("updateAccount", __updateAccount.bind(app));
  app.set("deleteAccount", __deleteAccount.bind(app));
  app.set("getAccounts", __getAccounts.bind(app));

  // setup global middlewares
  app.use([express.json(), morgan("tiny"), helmet()]);

  /**
   * @api
   * @http GET /
   * @description
   *  This route returns a reflexive description of the API and its routes.
   * @return {String} a JSON representation of the API
   */
  app.get("/", (req, res) => {
    const { name, version, description, author, license, bugs } = pkg;

    const r = app._router.stack
      .filter((layer) => layer.route)
      .map((layer) => {
        const { path, methods: m } = layer.route;
        let methods = [];
        for (k in m) {
          if (m[k]) {
            methods.push(k);
          }
        }
        return { path, methods };
      });

    let routes = {};

    r.forEach((o) => {
      if (!routes[o.path]) {
        routes[o.path] = [];
      }
      routes[o.path].push(...o.methods);
    });

    res.status(200).json({
      name,
      version,
      description,
      author,
      license,
      bugs,
      routes,
    });
  });

  /**
   * @api
   * @http POST /session
   * @description
   *  Given username & password from Authorization "Basic" header, authenticate
   *  account from database.
   * @headers
   *  @header Authorization - Basic header encoding 'username:password'
   * @return {JSON} A JSON representation of authenticated context
   *  @property {String} token The account session JWT
   *  @property {String} xsrf Associated XSRF token for further XSRF validations
   *  @property {Number} expiresIn session duration in seconds
   */
  app.post("/session", async (req, res) => {
    // username and password are sent through basic authentication scheme
    const [type, token] = req.get("authorization").split(" ");

    // is authorization header is "Basic" ?
    if (type !== "Basic") {
      // no : bad request detected here !
      res.status(400).json({
        status: 400,
        message: "E_BAD_REQUEST",
        reason: "R_BAD_AUTHORIZATION_HEADER_TYPE",
      });
    } else {
      // Decode Basic header and extract credentials
      const [username, password] = Buffer.from(token, "base64")
        .toString()
        .split(":");

      // check username and password against database
      const validateAccountCredentials = app.get("validateAccountCredentials");
      const { id } = await validateAccountCredentials({ username, password });
      if (id) {
        res.status(201).json(createSession({ id }));
      } else {
        res.status(401).json({ status: 401, message: "E_UNAUTHORIZED" });
      }
    }
  });

  /**
   * @api
   * @http GET /session
   * @description
   *  Given JWT from Authorization "Bearer" header, verify session validity
   *  and give back session informations to caller, including current user
   * @headers
   *  @header Authorization - Bearer token holding stateless session (JWT)
   * @return {JSON} A JSON representation of authenticated context
   *  @property {String} token The account session JWT
   *  @property {String} xsrf Associated XSRF token for further XSRF validations
   *  @property {Number} expiresIn session duration in seconds
   */
  app.get("/session", async (req, res) => {
    const [type, token] = req.get("authorization").split(" ");

    if (type === "Bearer") {
      try {
        const { sub, xsrf, iat, exp, iss, aud } = jwt.verify(token, APP_SECRET);
        const getAccount = app.get("getAccount");
        const me = await getAccount(sub);

        res.json({ me, xsrf, iat, exp, iss, aud });
      } catch (err) {
        const { name, message } = err;
        res.status(401).json({
          status: 401,
          name,
          message,
        });
      }
    } else {
      res.status(400).json({
        status: 400,
        message: "E_BAD_REQUEST",
        reason: "E_BAD_AUTHORIZATION_HEADER_TYPE",
      });
    }
  });

  /**
   * @api
   * @http POST /accounts
   * @description
   *  Create a new account
   * @request application/json
   *  @body {JSON}
   *    @property {String} token The account session JWT
   *    @property {String} xsrf Associated XSRF token for further XSRF validations
   *    @property {Number} expiresIn session duration in seconds
   * @response
   *  @status 201 | 409 | 500
   *    201 : new account created
   *    409 : username already taken
   *    500 : another error occured during account creation
   *  @body 201 - Account descriptor
   *    @property id        account ID
   *    @property username  account username
   *    @property password  account encrypted password
   *  @body 409 | 500 - An error descriptor
   */
  app.post("/accounts", async (req, res) => {
    const { username, password } = req.body;
    const createAccount = app.get("createAccount");

    try {
      const rs = await createAccount({ username, password });
      res.status(201).json(rs);
    } catch (err) {
      const { code } = err;
      let status = code === "ER_DUP_ENTRY" ? 409 : 500;
      res.status(status).json(err);
    }
  });

  /**
   * @api
   * @http GET /accounts
   * @description
   *  Fetch all accounts
   * @return {Array} An array containing all accounts
   */
  app.get("/accounts", async (req, res) => {
    const getAccounts = app.get("getAccounts");
    const data = await getAccounts();
    res.json(data);
  });

  /**
   * @api
   * @http GET /accounts/:id
   * @description
   *  Fetch a given account by ID
   * @return {Object} Account descriptor
   */
  app.get("/accounts/:id", async (req, res) => {
    const { id } = req.params;
    const getAccount = app.get("getAccount");
    const data = await getAccount(id);
    res.json(data);
  });

  app.delete("/accounts/:id", async (req, res) => {
    const { id } = req.params;
    const deleteAccount = app.get("deleteAccount");
    const ok = await deleteAccount(id);

    const status = ok ? 204 : 404;

    res.status(status);

    status === 404 ? res.json({ status, message: "E_NOT_FOUND" }) : res.end();
  });

  app.put("/accounts/:id", async (req, res) => {
    const { id } = req.params;
    const { username, password } = req.body;
    const updateAccount = app.get("updateAccount");
    const encryptedPassword = getPasswordHash(password);
    const ok = await updateAccount({
      id,
      username,
      password: encryptedPassword,
    });

    const status = ok ? 204 : 404;

    res.status(status);

    status === 404 ? res.json({ status, message: "E_NOT_FOUND" }) : res.end();
  });

  return app;
}

/**
 * @async
 * @function setup
 * @description
 *  This function setups the database connection and the application
 * @return {Application}
 */
async function setup() {
  // create connection
  const db = mysql.createConnection({
    host: MYSQL_HOST,
    user: MYSQL_USER,
    database: MYSQL_DATABASE,
    password: MYSQL_PASSWORD,
    port: MYSQL_PORT,
    multipleStatements: true,
  });

  // Initialize database if required (see schema.sql)
  const schema = fs.readFileSync("schema.sql", { encoding: "utf8", flag: "r" });
  const rs = await db.promise().query(schema);

  // Create express application
  const app = createApplication();

  app.set("db", db);

  return app;
}

setup()
  .then((app) => {
    app.listen(8080, () => {
      console.log("Listening on port 8080...");
    });
  })
  .catch((err) => {
    const { name, message } = err;
    console.error(`Error ! ${name} : ${message}`);
  });
