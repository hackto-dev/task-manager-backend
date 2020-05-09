const mongoose = require('mongoose');
const _ = require('lodash');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// JWT Secret
const jwtSecret = "32152033201321269965sdjanabjh21312321046412608";

const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        minlength: 1,
        trim: 1,
        unique: true
    },

    password: {
        type: String,
        required: true,
        minlength: 8,
    },

    sessions: [{
        token: {
            type: String,
            required: true
        },

        expiresAt: {
            type: Number,
            required: true
        }
    }]
});

// Instance Methods //
UserSchema.methods.toJSON = function() {
    const user = this;
    const userObject = user.toObject();

    // Return the document except password and sessions (Shouldn't be made available)
    return _.omit(userObject,['password','sessions']);
}

UserSchema.methods.generateAccessAuthToken = function () {
    const user = this;
    return new Promise((resolve, reject) => {
        // Create the JSON Web Token and return that
        jwt.sign({
            _id: user._id.toHexString()
        }, jwtSecret, {
            expiresIn: "15m"
        }, (err, token) => {
            if (!err) {
                resolve(token);
            } else {
                // there is an error
                reject();
            }
        })
    })
}

UserSchema.methods.generateRefreshAuthToken = function() {
    // This generates a 64 byte hex string - it doesn't save it to the database. saveSessionDatabase() does that
    return new Promise((resolve,reject) => {
        crypto.randomBytes(64,(err,buf) => {
            if(!err) {
                // No error
                let token = buf.toString('hex');
                return resolve(token);
            }
        });
    });
}

UserSchema.methods.createSession = function() {
    let user = this;

    return user.generateRefreshAuthToken().then((refreshToken) => {
        return saveSessionDatabase(user,refreshToken);
    }).then((refreshToken) => {
        // Saved to database successfully. Now return the refresh token.
        return refreshToken;
    }).catch((e) => {
        Promise.reject(e);
    })
}

// Model Methods //
UserSchema.statics.getJWTSecret = () => {
    return jwtSecret;
}

UserSchema.statics.findByIdAndToken = function(_id,token) {
    // Finds user by ID and token
    // Used in Auth Middleware (verifySession)

    const User = this;

    return User.findOne({
        _id,
        'sessions.token': token
    });
}

UserSchema.statics.findByCredentials = function(email,password) {
    let User = this;
    return User.findOne({ email }).then((user) => {
        if(!user) {
            return Promise.reject();
        } else {
            return new Promise((resolve,reject) => {
                bcrypt.compare(password, user.password,(err,res) => {
                    if(res) {
                        resolve(user);
                    } else {
                        reject();
                    }
                })
            });
        }
    });
}

UserSchema.statics.hasRefreshTokenExpired = (expiresAt) => {
    let secondsSinceEpoch = Date.now()/1000;

    if(expiresAt > secondsSinceEpoch) {
        // Not expired
        return false;
    } else {
        // Expired
        return true;
    }
}

// Middleware
UserSchema.pre('save',function(next) {
    let user = this;   
    let costFactor = 10;

    if(user.isModified('password')) {
        // If password field has been edited, then run this.
        // Generate salt and hash password

        bcrypt.genSalt(costFactor,(err,salt) => {
            bcrypt.hash(user.password,salt,(err,hash) => {
                user.password = hash;
                next();
            });
        });
    } else {
        next();
    }
});

// Helper Methods //
let saveSessionDatabase = (user,refreshToken) => {
    // Save session to database
    return new Promise((resolve,reject) => {
        let expiresAt = generateRefreshTokenExpiryTime();

        user.sessions.push({ 'token': refreshToken,expiresAt });

        user.save().then(() => {
            // Saved session successfully
            return resolve(refreshToken);
        }).catch((e) => {
            reject(e);
        })
    });
}

let generateRefreshTokenExpiryTime = () => {
    let daysUntilExpire = "10";
    let secondsUntilExpire = ((daysUntilExpire*24)*60*60);

    return ((Date.now()/1000) + secondsUntilExpire);
}

const User = mongoose.model("User",UserSchema);

module.exports = { User };