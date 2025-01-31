import jwt from 'jsonwebtoken';
import UserModal from '../models/User.js';
import bcrypt from 'bcryptjs';

const Register = async (req, res) => {
    try {
        const { FullName, email, password } = req.body;
        const imagePath = req.file.filename;
        console.log(imagePath);

        const existUser = await UserModal.findOne({ email });
        if (existUser) {
            return res.status(409).json({ success: false, message: "User already exists. Please log in." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new UserModal({
            FullName,
            email,
            password: hashedPassword,
            profile: imagePath,
        });

        await newUser.save();

        res.status(201).json({ success: true, message: 'User registered successfully', user: newUser });
    } catch (error) {
        console.error('Error during registration', error);
        res.status(500).json({ error: 'Error during registration' });
    }
};

const Login = async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log(email, password);

        if (!email || !password) {
            return res.status(400).json({ success: false, message: "All fields are required" });
        }

        const findUser = await UserModal.findOne({ email });
        if (!findUser) {
            return res.status(404).json({ success: false, message: "Account not found. Please register." });
        }

        const comparePassword = await bcrypt.compare(password, findUser.password);
        if (!comparePassword) {
            return res.status(401).json({ success: false, message: "Invalid password" });
        }

        // Generate token
        const token = jwt.sign({ userId: findUser._id }, process.env.JWT_SECRET, { expiresIn: '3d' });

        return res.status(200).json({ success: true, message: "Login successful", user: findUser, token });
    } catch (error) {
        console.error('Error during login', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
};

// Logout function is no longer necessary since tokens are now handled on the client-side
const Logout = async (req, res) => {
    try {
        res.status(200).json({ success: true, message: "Logout successful" });
    } catch (error) {
        console.error("Error logging out:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
};

const updateProfile = async (req, res) => {
    try {
        const userId = req.params.id;
        const { FullName, oldpassword, newpassword } = req.body;

        const existUser = await UserModal.findById(userId);
        if (!existUser) {
            return res.status(404).json({ success: false, message: "Account not found." });
        }

        if (oldpassword) {
            const comparePassword = await bcrypt.compare(oldpassword, existUser.password);
            if (!comparePassword) {
                return res.status(401).json({ success: false, message: "Old password is incorrect." });
            }
        }

        if (FullName) {
            existUser.FullName = FullName;
        }
        if (oldpassword && newpassword) {
            const hashedPassword = await bcrypt.hash(newpassword, 10);
            existUser.password = hashedPassword;
        } else if (oldpassword && !newpassword) {
            return res.status(400).json({ success: false, message: "New password is required when old password is provided." });
        }

        await existUser.save();

        res.status(200).json({ success: true, message: "Profile updated successfully.", user: existUser });
    } catch (error) {
        console.error("Error updating profile:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
};

export { Register, Login, Logout, updateProfile };
