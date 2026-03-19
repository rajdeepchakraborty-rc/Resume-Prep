const userModel = require('../models/user.model');
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const tokenBlacklistModel = require('../models/blacklist.model')

/**
 * @name registerUserController
 * @description Register a new user, expecting username, email and password in the request body.
 * @access Public
 */
async function registerUserController(req, res) {
    try {
        const {username, email, password} = req.body

        if (!username || !email || !password) {
            return res.status(400).json({
                message: 'Username, email and password are required'
            })
        }

        const isUserAlreadyExists = await userModel.findOne({
            $or: [
                { username },
                { email }
            ]
        })

        if(isUserAlreadyExists) {
            if(isUserAlreadyExists.username === username) {
                return res.status(400).json({
                    message: 'Username already exists'
                })
            }

            return res.status(400).json({
                message: 'Email already exists'
            })
        }

        const hash = await bcrypt.hash(password, 10)

        const user = new userModel({
            username,
            email,
            password: hash
        })

        await user.save()

        const token = jwt.sign({
            id: user._id,
            username: user.username,
        },
        process.env.JWT_SECRET,
        {expiresIn: '1d'})

        res.cookie('token', token)

        res.status(201).json({
            message: 'User registered successfully',
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
            }
        })
    } catch (error) {
        console.error('Register error:', error)
        res.status(500).json({
            message: 'Something went wrong while registering the user'
        })
    }
}


/**
 * @name loginUserController
 * @description Login a user, expecting email and password in the request body.
 * @access Public
 */
async function loginUserController(req, res) {

    const {email, password} = req.body

    const user = await userModel.findOne({email})

    if(!user) {
        return res.status(400).json({
            message: 'Invalid email or password'
        })
    }

    const isPasswordValid = await bcrypt.compare(password, user.password)

    if(!isPasswordValid) {
        return res.status(400).json({
            message: 'Invalid email or password'
        })
    }

    const token = jwt.sign({
        id: user._id,
        username: user.username,
    },
    process.env.JWT_SECRET,
    {expiresIn: '1d'})

    res.cookie('token', token)
    res.status(200).json({
        message: 'User logged in successfully',
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        }
    })
}

/**
 * @name logoutUserController
 * @description clear token from user cookies and add it to blacklist
 * @access Public 
 */
async function logoutUserController(req, res) {
    const token = req.cookies.token
    if (token) {
        await tokenBlacklistModel.create({ token })
    }

    res.clearCookie('token')

    res.status(200).json({
        message: 'User logged out successfully'
    })
}

/**
 * @name getMeController
 * @description Get the currently logged in user's information.
 * @access Private
 */
async function getMeController(req, res) {
    const user = await userModel.findById(req.user.id)

    res.status(200).json({
        message: 'User data fetched successfully',
        user: {
            id: user._id,
            username: user.username,
            email: user.email
        }
    })
}

module.exports = {
    registerUserController,
    loginUserController,
    logoutUserController,
    getMeController
}