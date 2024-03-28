const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const app = express();

const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

// Configure body-parser middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const cors = require("cors");

const corsOptions = {
  origin: "*", // Replace with allowed origins if necessary 
  credentials: true, // Allow cookies for authenticated requests (if applicable)
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  methods: "GET, POST, PUT, DELETE, OPTIONS", // Allowed HTTP methods
};

app.use(cors(corsOptions));

const dbPath = path.join(__dirname, "data.db");

let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3000, () => {
      console.log("Server Running at http://localhost:3000/");
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();


//Miideleware for authentication and authorization

const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401);
    response.send("Invalid JWT Token");
  } else {
    jwt.verify(jwtToken, "MY_SECRET_KEY", async (error, payload) => {
      if (error) {
        response.status(401);
        response.send(error);
        response.send("Invalid JWT Token");
      } else {
        next();
        console.log(payload);
      }
    });
  }
};


//API endpoint to register a user

app.post("/register", async (request, response) => {
  const { username, email, password } = request.body;
  const dbUser = await db.get(
    `Select * From users where username = "${username}";`
  );
  if (dbUser === undefined) {
    if (password.length >= 6) {
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.run(`
INSERT INTO users
(username,email,password )
values
("${username}","${email}","${hashedPassword}");
`);
      response.status(200);
      response.send("User registered successfully");
    } else {
      response.status(400);
      response.send("Password is too short");
    }
  } else {
    response.status(400);
    response.send("User already exists");
  }
});


//API endpoint to login the user

app.post("/login", async (request, response) => {
  const { username, password } = request.body;
  const dbUser = await db.get(
    `Select * From users where username = "${username}";`
  );
  if (dbUser !== undefined) {
    const isPasswordMatch = await bcrypt.compare(password, dbUser.password);
    if (isPasswordMatch) {
      let jwtToken = jwt.sign(username, "MY_SECRET_KEY");
      response.send({ jwtToken });
    } else {
      response.status(400);
      response.send("Invalid password");
    }
  } else {
    response.status(400);
    response.send("Invalid user");
  }
});



// User Logout: Since JWTs are stateless, logout typically involves the client-side destroying the token.
// Logout endpoint

app.post("/logout", authenticateToken, async (request, response) => {
  const { username } = request.body;
  const getUserQuery = `
  SELECT *
  FROM users
  WHERE username='${username}';
  `;
  const user = await db.get(getUserQuery);
  console.log(user);
  if (user === undefined) {
    response.status(400);
    response.send("Invalid User");
  } else {
    response.send(`Logged out ${username}`);
  }
});



//API end point for public api with filters for category and limits.

app.get("/entries", authenticateToken, async (request, response) => {
  try {
    const { category = "", limit = 5 } = request.query;

    const apiResponse = await fetch("https://api.publicapis.org/entries");
    const responseData = await apiResponse.json();

    const entriesList = responseData.entries;
    let filteredList = entriesList.filter((obj) =>
      obj.Category.toLowerCase().includes(category.toLowerCase())
    );

    filteredList = filteredList.slice(0, limit);

    if (filteredList.length > 0) {
      response.json(filteredList);
    } else {
      response.json("There are no entries for this filter!");
    }
  } catch (error) {
    console.error("Error fetching data:", error);
    response.status(500).send("Error fetching data");
  }
});



//Swagger jsdoc options

const swaggerOptions = {
  swaggerDefinition: {
    servers: [
      {
        url: "http://localhost:3000/",
      },
    ],
    info: {
      title: "Backend Developer Intern Assessment - Lalitendra",
      version: "1.0.0",
      description: "Documentation for API endpoints",
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
  },
  securityDefinitions: {
    bearerAuth: {
      type: "apiKey",
      name: "Authorization",
      in: "header",
      description: 'Enter JWT token in the format "Bearer {token}"',
    },
  },
  apis: ["index.js"],
};

// Initialize Swagger
const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.get("/swagger.json", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.send(swaggerSpec);
});
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocs));

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register a new user
 *     parameters:
 *       - in: body
 *         name: user
 *         description: The user to create.
 *         schema:
 *           type: object
 *           required:
 *             - username
 *             - email
 *             - password
 *           properties:
 *             username:
 *               type: string
 *             email:
 *               type: string
 *             password:
 *               type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 *       500:
 *         description: Internal server error
 */

/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login and get JWT token
 *     parameters:
 *       - in: body
 *         name: user
 *         description: The user credentials.
 *         schema:
 *           type: object
 *           required:
 *             - username
 *             - password
 *           properties:
 *             username:
 *               type: string
 *             password:
 *               type: string
 *     responses:
 *       200:
 *         description: JWT token generated
 *       401:
 *         description: Invalid username or password
 *       500:
 *         description: Internal server error
 */

/**
 * @swagger
 * /logout:
 *   post:
 *     summary: Logouts the User
 *     parameters:
 *       - in: body
 *         name: user
 *         description: The user credentials.
 *         schema:
 *           type: object
 *           required:
 *             - username
 *             - password
 *           properties:
 *             username:
 *               type: string
 *             password:
 *               type: string
 *     responses:
 *       200:
 *         description: Logged out
 *       400:
 *         description: Invalid User
 *       401:
 *         description: Invalid JWT Token
 *       500:
 *         description: Internal server error
 */

/**
 * @swagger
 * /entries:
 *   get:
 *     summary: Retrieve data from a public API
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter data by category
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *         description: Limit the number of results
 *     produces:
 *          -application/json
 *     responses:
 *       200:
 *         description: Successfully retrieved data
 *         content:
 *           application/json:
 *               schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   API:
 *                     type: string
 *                   Description:
 *                     type: string
 *                   Auth:
 *                     type: string
 *                   HTTPS:
 *                     type: boolean
 *                   Cors:
 *                     type: string
 *                   Link:
 *                     type: string
 *                   Category:
 *                     type: string
 *       401:
 *         description: Unauthorized. Token is missing or invalid
 */
