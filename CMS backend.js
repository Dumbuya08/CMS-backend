// Import required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');

// Load environment variables
dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true
        });
        console.log('MongoDB connected successfully');
    } catch (error) {
        console.error('MongoDB connection failed:', error.message);
        process.exit(1);
    }
};
connectDB();

// User Schema
const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    role: { type: String, enum: ['admin', 'facilitator'], default: 'facilitator' }
});
const User = mongoose.model('User', UserSchema);

// Laptop Schema
const LaptopSchema = new mongoose.Schema({
    serialNumber: String,
    model: String,
    allocatedTo: String,
    status: { type: String, enum: ['allocated', 'returned'], default: 'allocated' },
    issues: String
});
const Laptop = mongoose.model('Laptop', LaptopSchema);

// User Registration
app.post('/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    try {
        const user = new User({ name, email, password: hashedPassword, role });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(400).json({ error: 'Error registering user' });
    }
});

// User Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, role: user.role });
});

// Middleware for authentication
const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Access denied' });

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

// Add Laptop Record
app.post('/laptops', authMiddleware, async (req, res) => {
    const { serialNumber, model, allocatedTo, status, issues } = req.body;
    try {
        const laptop = new Laptop({ serialNumber, model, allocatedTo, status, issues });
        await laptop.save();
        res.status(201).json({ message: 'Laptop record added successfully' });
    } catch (error) {
        res.status(400).json({ error: 'Error adding laptop record' });
    }
});

// Fetch All Laptop Records
app.get('/laptops', authMiddleware, async (req, res) => {
    const laptops = await Laptop.find();
    res.json(laptops);
});

// Update Laptop Record
app.put('/laptops/:id', authMiddleware, async (req, res) => {
    try {
        const updatedLaptop = await Laptop.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(updatedLaptop);
    } catch (error) {
        res.status(400).json({ error: 'Error updating laptop record' });
    }
});

// Delete Laptop Record
app.delete('/laptops/:id', authMiddleware, async (req, res) => {
    try {
        await Laptop.findByIdAndDelete(req.params.id);
        res.json({ message: 'Laptop record deleted' });
    } catch (error) {
        res.status(400).json({ error: 'Error deleting laptop record' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
