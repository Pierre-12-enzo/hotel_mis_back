require("dotenv").config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const connDB = require('./config/db');


const app = express();

//Middleware
app.use(express.json());
app.use(cors({
    origin: "http://localhost:5173", // your frontend URL
    credentials: true, // allow cookies
}));
app.use(cookieParser());// to parse cookies


// Routes
app.use('/api/auth', require('./routes/auth'));
//app.use('/api/customers', require('./routes/customers'));
//app.use('/api/folios', require('./routes/folios'));
//app.use('/api/services', require('./routes/services'));
//app.use('/api/payments', require('./routes/payments'));



//Run the server

connDB();
const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
    console.log(`Serever is running on port ${PORT}`)
})
//console.log("enzo-amic");