import express from 'express'

import { createUser, getUserByEmail} from '../db/users'
import {random, authentication} from '../helpers'

export const register = async( req: express.Request, res: express.Response) =>{
    try{
        const {email, password, username} = req.body
        
        console.log("The request body",JSON.stringify(req.body))

        if(!email || !password || ! username){
           return res.sendStatus(400)
        }

        const existingUser = await getUserByEmail(email)
        console.log("The existingUser",JSON.stringify(existingUser))
        if(existingUser){
            return res.sendStatus(400)
        }

        const salt = random()
        const user = await createUser({
            email,
            username,
            authentication:{
                salt,
                password : authentication(salt, password),
            },
        })

        return res.status(200).json(user).end()
    }catch(error){
        console.log('Error in Register', error)
        return res.sendStatus(400)
    }
}

export const login = async( req: express.Request, res: express.Response) =>{
    try{
        const {email, password} = req.body
        
        console.log("The request body",JSON.stringify(req.body))

        if(!email || !password ){
           return res.sendStatus(400)
        }

        const existingUser = await getUserByEmail(email).select('+authentication.salt +authentication.password')
        console.log("The existingUser",JSON.stringify(existingUser))

        if(!existingUser){
            return res.sendStatus(400)
        }

        const expectedHash = authentication(existingUser.authentication.salt, password)
        console.log("The existingUser",JSON.stringify(expectedHash))
        if(existingUser.authentication.password !== expectedHash)
        {
            console.log("The existingUser password differs from the provided password",JSON.stringify(expectedHash))
            return res.sendStatus(403)
        }
    
        const salt = random()

        existingUser.authentication.sessionToken = authentication(salt, existingUser._id.toString())
        
        await existingUser.save()
        console.log("The sessionToken save successfully",JSON.stringify(expectedHash))
        res.cookie('DUBEM-AUTH', existingUser.authentication.sessionToken, {domain: 'localhost', path: '/'})

        return res.status(200).json(existingUser).end()

    }catch(error){
        console.log('Error in Register', error)
        return res.sendStatus(400)
    }
}