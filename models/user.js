const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const UserSchema = new mongoose.Schema({
 name: { type: String, required: true },
 email: { type: String, required: true, unique: true },
 password: { type: String, required: true },
 refreshToken: { type: String }, // Store Refresh Token
});

// Hash password before saving
UserSchema.pre("save", async function (next) {
 if (!this.isModified("password")) return next();
 const salt = await bcrypt.genSalt(10);
 this.password = await bcrypt.hash(this.password, salt);
 next();
});

// Compare password
UserSchema.methods.matchPassword = async function (enteredPassword) {
 return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model("User", UserSchema);
