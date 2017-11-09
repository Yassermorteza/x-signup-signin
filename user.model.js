const mongoose = require('mongoose');
const Schema = mongoose.Schema

const userSchema = new Schema({
	username: { type: String, required: true, index: { unique: true } },
	email:{ type: String, required: true, index: { unique: true } }, 
    password: { type: String, required: true },
    loginAttempts: { type: Number, required: true, default: 0 },
    lockUntil: { type: Number }
});

module.exports = mongoose.model('user', userSchema);



