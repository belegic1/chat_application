const { User } = require("../models")
const bcrypt = require("bcryptjs")
const {UserInputError, AuthenticationError} = require("apollo-server")
const jwt = require("jsonwebtoken")
const {Op} = require("sequelize")

module.exports = {
    Query: {
        getUsers: async (_, __, context) => {
            try {
                let user
                if (context.req && context.req.headers.authorization) {
                    const token = context.req.headers.authorization.split('Bearer ')[1]
                    jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
                        if (err) {
                            throw new AuthenticationError('Unauthenticated')
                        }
                        user = decodedToken
                    })
                }

                const users = await User.findAll({
                    where: { username: { [Op.ne]: user.username } },
                })

                return users
            } catch (err) {
                console.log(err)
                throw err
            }
        },
        login: async (_, args) => {
            const { username, password } = args
            let errors = {}

            try {
                if (username.trim() === '')
                    errors.username = 'username must not be empty'
                if (password === '') errors.password = 'password must not be empty'

                if (Object.keys(errors).length > 0) {
                    throw new UserInputError('bad input', { errors })
                }

                const user = await User.findOne({
                    where: { username },
                })

                if (!user) {
                    errors.username = 'user not found'
                    throw new UserInputError('user not found', { errors })
                }

                const correctPassword = await bcrypt.compare(password, user.password)

                if (!correctPassword) {
                    errors.password = 'password is incorrect'
                    throw new AuthenticationError('password is incorrect', { errors })
                }

                const token = jwt.sign({ username }, process.env.JWT_SECRET, {
                    expiresIn: 60 * 60,
                })

                return {
                    ...user.toJSON(),
                    createdAt: user.createdAt.toISOString(),
                    token,
                }
            } catch (err) {
                console.log(err)
                throw err
            }
        },
    },
    Mutation: {
        register: async (_, args) => {
            let { username, email, password, confirmPassword } = args
            let errors = {}
            try {
                if (email.trim() === "") {
                    errors.emaill = "Email is empty"
                }
                if (username.trim() === "") {
                    errors.username = "Username is empty"
                }
                if (password.trim() === "") {
                    errors.password = "Password is empty"
                }
                if (confirmPassword.trim() === "") {
                    errors.confirmPassword = "Confirm Password is empty"
                }
                if (password !== confirmPassword) {
                    errors.confirmPassword = "Passwords must match"
                }

                const userByUsername = await User.findOne({ where: { username } })
                const userByEmail = await User.findOne({ where: { email } })
                if (userByUsername) {
                    errors.username = "Username is taken"
                }
                if (userByEmail) {
                    errors.email = "Email is taken"
                }

                if (Object.keys(errors).length > 0) {
                    errors.map(error => {
                        console.log("Error", error);
                        throw error
                    })
                }
                password = await bcrypt.hash(password, 6)

              const user =  await User.create({username,email,password})
                return user
            } catch (error) {
                console.log(error);
                throw new UserInputError({errors: error.message})
            }
    }
    }
};