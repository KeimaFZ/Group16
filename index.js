const express = require('express');
const app = express();
const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const { ObjectId } = require('mongodb'); // Import ObjectId
const path = require('path');

//const port = 4000;
const port = process.env.PORT || 4000 ;
//const ejs = require('ejs');

// Set the view engine to EJS
//app.set('view engine', 'ejs');

// Serve static files from the public directory
//app.use(express.static(path.join(__dirname, 'public')));

// Route to render the login page
//app.get('/login', (req, res) => {
  //res.render('index'); // Renders the 'index.ejs' file inside the 'views' folder
//});

// Set up middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const MongoURI = process.env.MONGODB_URI

// Swagger set up
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Hostel Visitor Management API',
      version: '1.0.0',
      description: 'This is a simple CRUD API application made with Express and documented with Swagger',
    },
    servers: [
      {
        url: `https://group16is.azurewebsites.net/`,
      },
    ],
    components: {
      securitySchemes: {
        jwt:{
					type: 'http',
					scheme: 'bearer',
					in: "header",
					bearerFormat: 'JWT'
        },
      },
    },
		security:[{
			"jwt": []
  }]
},
  apis: ['./index.js'], // path to your API routes

};



const swaggerDocs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));


//middleware
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7, authHeader.length); // "Bearer " is 7 characters
    //... (rest of your verification logic)
  } else {
    return res.status(403).json({ error: 'No token provided' });
  }

  const token = authHeader.split(' ')[1]; // Expecting "Bearer TOKEN_STRING"
  try {
    const decoded = jwt.verify(token, secret);
    req.user = decoded;
  } catch (error) {
    return res.status(401).json({ error: 'Failed to authenticate token' });
  }

  next();
};


// Secret key for JWT signing and encryption
const secret = 'your-secret-key'; // Store this securely

app.use(bodyParser.json());


const uri = "mongodb://FifeeZaheed:keima@ac-86lqujp-shard-00-00.cbn8onp.mongodb.net:27017,ac-86lqujp-shard-00-01.cbn8onp.mongodb.net:27017,ac-86lqujp-shard-00-02.cbn8onp.mongodb.net:27017/?replicaSet=atlas-ir7cjs-shard-0&ssl=true&authSource=admin";
// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});
async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("HOSTELVISITORMANAGEMENT").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.dir);
let db;
let Visitorregistration;
let adminuser;
let securities;
let hosts;




// Connect to MongoDB and initialize collections
client.connect()
  .then(() => {
    console.log('Connected to MongoDB');
    db = client.db('HOSTELVISITORMANAGEMENT');
    

  // Initialize collections after establishing the connection
  Visitorregistration = db.collection('visitors');
  adminuser = db.collection('admins');
  securities = db.collection('securities'); // Add this line if you're using a 'securities' collection
  hosts = db.collection('hosts'); // Add this line if you're using a 'hosts' collection



  // Now you can safely start your server here, after the DB connection is established
  app.listen(port, () => {
    console.log(`Server is running on https://group16is.azurewebsites.net/`);
  });
});


// In-memory data storage (replace with a database in production)
const visitors = [];
const securitiesData = [];
const hostsData = [];

app.use(express.json());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));


/**
 * @swagger
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 */


/**
 * @swagger
 * /security/register:
 *   post:
 *     summary: Register a new security account
 *     tags: [Security]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: Security registered successfully
 *       400:
 *         description: Security already exists
 */



// Scurity Register New Account
app.post('/security/register', async (req, res) => {
  const securities = db.collection('securities'); // Assuming a 'securities' collection
  const { username, password } = req.body;

  const existingSecurity = await securities.findOne({ username });
  if (existingSecurity) {
    return res.status(400).json({ error: 'Security already exists' });
  }

  await securities.insertOne({ username, password });
  res.status(201).json({ message: 'Security registered successfully' });
});



/**
 * @swagger
 * /security/login:
 *   post:
 *     summary: Security login
 *     tags: [Security]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Security authenticated successfully
 *       401:
 *         description: Invalid username or password
 */

// Security Login
app.post('/security/login', async (req, res) => {
  const securities = db.collection('securities'); // Assuming a 'securities' collection
  const { username, password } = req.body;

  const security = await securities.findOne({ username, password });
  if (!security) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  // Create token if the security was found
  const token = jwt.sign({ userId: security._id }, secret, { expiresIn: '1h' });

  res.json({ message: 'Security authenticated successfully', accessToken: token });
});



// Existing route in your code
app.get('/login', (req, res) => {
  res.render('login'); // This will render login.ejs when /login is accessed
});


/**
 * @swagger
 * /host/register:
 *   post:
 *     summary: Register a new host
 *     tags:
 *       - Host
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - username
 *               - password
 *               - phoneNumber
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               phoneNumber:
 *                 type: string
 *                 description: Phone number of the host
 *     responses:
 *       201:
 *         description: Host registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 accessToken:
 *                   type: string
 *       400:
 *         description: Host already exists or missing required fields
 *       500:
 *         description: Error occurred while registering the host
 */



// Host registration endpoint
app.post('/host/register', async (req, res) => {
  const hosts = db.collection('hosts');
  const { username, password, phoneNumber } = req.body;

  try {
    // Check if the user already exists
    const existingHost = await hosts.findOne({ username });
    if (existingHost) {
      return res.status(400).send('Host already exists');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new host with username, hashed password, and phone number
    const result = await hosts.insertOne({
      username,
      password: hashedPassword,
      phoneNumber,
    });
    const newHostId = result.insertedId;

    // Create a token
    const token = jwt.sign({ userId: newHostId }, secret, { expiresIn: '1h' });

    res.status(201).json({ message: 'Host registered successfully', accessToken: token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'An error occurred while registering the host' });
  }
});


/**
 * @swagger
 * /host/login:
 *   post:
 *     summary: Authenticate a host
 *     tags:
 *       - Host
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Host authenticated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 accessToken:
 *                   type: string
 *       401:
 *         description: Invalid username or password
 *       500:
 *         description: Error occurred while logging in
 */


    // Host login endpoint
    app.post('/host/login', async (req, res) => {
      const { username, password } = req.body;

      try {
          // Find host with the given username
          const host = await hosts.findOne({ username });

          if (!host || host.password !== password) {
              return res.status(401).send('Invalid username or password');
          }

          // Create a token
          const token = jwt.sign({ userId: host._id }, secret, { expiresIn: '1h' });

          res.json({ message: 'Host authenticated successfully', accessToken: token });
      } catch (error) {
          console.error('Login error:', error);
          res.status(500).json({ error: 'An error occurred while logging in' });
      }
  });

/**
 * @swagger
 * /registervisitor:
 *   post:
 *     summary: Register a new visitor
 *     tags: [Visitor]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Visitor'
 *     responses:
 *       201:
 *         description: Visitor registered successfully
 *       500:
 *         description: Error occurred while registering the visitor
 */


// Protected route for registering a visitor - token required
app.post('/registervisitor', verifyToken, async (req, res) => {
  try {
    const visitors = db.collection('visitors');
    const { username, password, Name, Age, Gender, Address, Zipcode, Relation } = req.body;

    await visitors.insertOne({ username, password, Name, Age, Gender, Address, Zipcode, Relation });
    res.status(201).json({ message: 'Visitor registered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while registering the visitor' });
  }
});

/**
 * @swagger
 * /viewvisitor:
 *   get:
 *     summary: View all visitors
 *     tags: [Visitor]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of all visitors
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Visitor'
 *       500:
 *         description: Error occurred while fetching visitors
 */


// Protected route for viewing visitors - token required
app.get('/viewvisitor', verifyToken, async (req, res) => {
  try {
    const visitors = db.collection('visitors');
    const results = await visitors.find().toArray();

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while fetching visitors' });
  }
});


/**
 * @swagger
 * /issuevisitorpass:
 *   post:
 *     summary: Issue a visitor pass
 *     tags: [Pass]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - visitorId
 *               - issuedBy
 *               - validUntil
 *             properties:
 *               visitorId:
 *                 type: string
 *               issuedBy:
 *                 type: string
 *               validUntil:
 *                 type: string
 *                 format: date
 *     responses:
 *       201:
 *         description: Visitor pass issued successfully
 *       500:
 *         description: Error occurred while issuing the pass
 */


// Admin issue visitor pass
// Admin Issue Visitor Pass
app.post('/issuevisitorpass', verifyToken, async (req, res) => {
  const { visitorId, issuedBy, validUntil } = req.body;

  try {
    const visitorPasses = db.collection('visitorpasses');

    const newPass = {
      visitorId,
      issuedBy,
      validUntil,
      issuedAt: new Date(),
    };

    await visitorPasses.insertOne(newPass);
    res.status(201).json({ message: 'Visitor pass issued successfully' });
  } catch (error) {
    console.error('Issue Pass Error:', error.message);
    res.status(500).json({ error: 'An error occurred while issuing the pass', details: error.message });
  }
});

/**
 * @swagger
 * /retrievepass/{visitorId}:
 *   get:
 *     summary: Retrieve a visitor pass
 *     tags: [Pass]
 *     parameters:
 *       - in: path
 *         name: visitorId
 *         required: true
 *         schema:
 *           type: string
 *         description: The visitor ID
 *     responses:
 *       200:
 *         description: Visitor pass details
 *       404:
 *         description: No pass found for this visitor
 *       500:
 *         description: Error occurred while retrieving the pass
 */


//Visitor to Retrieve Their Pass
// Visitor Retrieve Pass
app.get('/retrievepass/:visitorId', async (req, res) => {
  const visitorId = req.params.visitorId;

  try {
    const visitorPasses = db.collection('visitorpasses');
    const pass = await visitorPasses.findOne({ visitorId });

    if (!pass) {
      return res.status(404).json({ error: 'No pass found for this visitor' });
    }

    res.json(pass);
  } catch (error) {
    console.error('Retrieve Pass Error:', error.message);
    res.status(500).json({ error: 'An error occurred while retrieving the pass', details: error.message });
  }
});


/**
 * @swagger
 * /updatevisitor/{visitorId}:
 *   patch:
 *     summary: Update visitor details
 *     tags: [Visitor]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: visitorId
 *         required: true
 *         schema:
 *           type: string
 *         description: The visitor ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/VisitorUpdate'
 *     responses:
 *       200:
 *         description: Visitor updated successfully
 *       404:
 *         description: No visitor found with this ID
 *       500:
 *         description: Error occurred while updating the visitor
 */


//Update visitor
app.patch('/updatevisitor/:visitorId', verifyToken, async (req, res) => {
  const visitorId = req.params.visitorId;
  const updateData = req.body;

  try {
    const updatedVisitor = await db.collection('visitors').updateOne(
      { _id: new ObjectId(visitorId) }, // Use 'new' with ObjectId
      { $set: updateData }
    );

    if (updatedVisitor.matchedCount === 0) {
      return res.status(404).json({ message: 'No visitor found with this ID' });
    }

    res.json({ message: 'Visitor updated successfully', updatedVisitor });
  } catch (error) {
    console.error('Update error:', error); // Log the entire error object
    res.status(500).json({ error: 'An error occurred while updating the visitor', details: error.toString() });
  }
});

/**
 * @swagger
 * /deletevisitor/{visitorId}:
 *   delete:
 *     summary: Delete a visitor
 *     tags: [Visitor]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: visitorId
 *         required: true
 *         schema:
 *           type: string
 *         description: The visitor ID
 *     responses:
 *       200:
 *         description: Visitor deleted successfully
 *       404:
 *         description: No visitor found with this ID
 *       500:
 *         description: Error occurred while deleting the visitor
 */


// Delete visitor
app.delete('/deletevisitor/:visitorId', verifyToken, async (req, res) => {
  const visitorId = req.params.visitorId;

  try {
    const deletionResult = await db.collection('visitors').deleteOne(
      { _id: new ObjectId(visitorId) } // Use 'new' with ObjectId
    );

    if (deletionResult.deletedCount === 0) {
      return res.status(404).json({ message: 'No visitor found with this ID' });
    }

    res.json({ message: 'Visitor deleted successfully' });
  } catch (error) {
    console.error('Delete error:', error); // Log the entire error object
    res.status(500).json({ error: 'An error occurred while deleting the visitor', details: error.toString() });
  }
});

// Manage account roles swagger
/**
 * @swagger
 * /admin/manage-roles:
 *   patch:
 *     summary: Manage user roles
 *     tags: [Admin]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               userId:
 *                 type: string
 *               newRole:
 *                 type: string
 *     responses:
 *       200:
 *         description: User role updated successfully
 *       401:
 *         description: Unauthorized
 *       404:
 *         description: User not found
 *       500:
 *         description: Error occurred while updating user role
 */

// Manage account roles
app.patch('/admin/manage-roles', verifyToken, async (req, res) => {
  const { userId, newRole } = req.body;

  // Ensure the user performing the operation is an admin
  if (!req.user.isAdmin) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const updateResult = await db.collection('users').updateOne(
      { _id: new ObjectId(userId) },
      { $set: { role: newRole } }
    );

    if (updateResult.matchedCount === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'User role updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while updating user role', details: error.toString() });
  }
});

// Get host contact swagger
/**
 * @swagger
 * /gethostcontact:
 *   get:
 *     summary: Retrieve host contact number using visitor pass ID
 *     tags: [Security]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: visitorPassId
 *         required: true
 *         schema:
 *           type: string
 *         description: Visitor Pass ID to retrieve host contact
 *     responses:
 *       200:
 *         description: Host contact number retrieved successfully
 *       404:
 *         description: No visitor pass found with this ID
 *       500:
 *         description: Error occurred while retrieving host contact number
 */

// Route to retrieve host contact number using visitor pass ID
app.get('/gethostcontact', verifyToken, async (req, res) => {
  const { visitorPassId } = req.query;

  try {
    // Assuming you have a collection that associates visitor passes with hosts
    const visitorPasses = db.collection('visitorpasses');
    const passInfo = await visitorPasses.findOne({ _id: new ObjectId(visitorPassId) });

    if (!passInfo) {
      return res.status(404).json({ error: 'No visitor pass found with this ID' });
    }

    // Assuming you have a host's contact number stored in a 'hosts' collection
    const hosts = db.collection('hosts');
    const hostInfo = await hosts.findOne({ _id: new ObjectId(passInfo.hostId) });

    if (!hostInfo) {
      return res.status(404).json({ error: 'No host found for this visitor pass' });
    }

    // Sending back only the contact number as specified in the requirement
    res.json({ contactNumber: hostInfo.contactNumber });
  } catch (error) {
    console.error('Get Host Contact Error:', error.message);
    res.status(500).json({ error: 'An error occurred while retrieving host contact number', details: error.message });
  }
});


/**
 * @swagger
 * components:
 *   securitySchemes:
 *     bearerAuth:
 *       type: http
 *       scheme: bearer
 *       bearerFormat: JWT
 *   schemas:
 *     Visitor:
 *       type: object
 *       required:
 *         - Name
 *         - Age
 *         - Gender
 *         - Address
 *         - Zipcode
 *         - Relation
 *       properties:
 *         Name:
 *           type: string
 *         Age:
 *           type: integer
 *         Gender:
 *           type: string
 *         Address:
 *           type: string
 *         Zipcode:
 *           type: string
 *         Relation:
 *           type: string
 *     VisitorUpdate:
 *       type: object
 *       properties:
 *         Name:
 *           type: string
 *         Age:
 *           type: integer
 *         Gender:
 *           type: string
 *         Address:
 *           type: string
 *         Zipcode:
 *           type: string
 *         Relation:
 *           type: string
 */