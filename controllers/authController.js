const User = require("../models/user");
const { generateAccessToken, generateRefreshToken } = require("../utils/generateToken");

const registerUser = async (req, res) => {
 const { name, email, password } = req.body;

 const userExists = await User.findOne({ email });
 if (userExists) {
  return res.status(400).json({ message: "User already exists" });
 }

 const user = await User.create({ name, email, password });

 if (user) {
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  user.refreshToken = refreshToken;
  await user.save();

  res.json({ accessToken, refreshToken });
 } else {
  res.status(400).json({ message: "Invalid user data" });
 }
};

const loginUser = async (req, res) => {
 const { email, password } = req.body;

 const user = await User.findOne({ email });

 if (user && (await user.matchPassword(password))) {
  const accessToken = generateAccessToken(user);
  const refreshToken = generateRefreshToken(user);

  user.refreshToken = refreshToken;
  await user.save();

  res.json({ accessToken, refreshToken });
 } else {
  res.status(401).json({ message: "Invalid email or password" });
 }
};

const refreshToken = async (req, res) => {
 const { refreshToken } = req.body;

 if (!refreshToken) return res.status(403).json({ message: "Access Denied" });

 try {
  const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
  const user = await User.findById(decoded.userId);

  if (!user || user.refreshToken !== refreshToken) {
   return res.status(403).json({ message: "Invalid refresh token" });
  }

  const newAccessToken = generateAccessToken(user);
  res.json({ accessToken: newAccessToken });
 } catch (error) {
  res.status(403).json({ message: "Invalid refresh token" });
 }
};

const logoutUser = async (req, res) => {
 const { refreshToken } = req.body;

 const user = await User.findOne({ refreshToken });
 if (user) {
  user.refreshToken = "";
  await user.save();
 }

 res.json({ message: "Logged out successfully" });
};

module.exports = { registerUser, loginUser, refreshToken, logoutUser };
