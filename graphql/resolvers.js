const { User } = require("../models")
const bcrypt = require("bcrypt")
const {UserInputError} = require("apollo-server")

module.exports = {
    Query: {
        getUsers: async () => {
            try {
                const users = await User.findAll()
                return users
            } catch (error) {
                console.log(error.message);
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