import express  from "express";
import {get, merge} from "lodash"

import { getUserBySessionToken } from "../db/users";

export const isOwner = async( req: express.Request, res: express.Response, next: express.NextFunction) =>{

    try{
         const { id} = req.params

         const currentUserId = await get(req, 'identity._id') as string
         console.log("The currentUserId",JSON.stringify(currentUserId))
         if(!currentUserId)
         {
            return res.sendStatus(403)
         }

         if(currentUserId === id)
         {
            console.log("The currentUserId is not same with id")
            return res.sendStatus(403)
         }

         return next()
    }catch(error){
      console.log(error)
      return res.sendStatus(403)
    }
}


export const isAuthenticated = async( req: express.Request, res: express.Response, next: express.NextFunction) =>{

    try{
         const sessionToken = req.cookies['DUBEM-AUTH']

         if(!sessionToken)
         {
            return res.sendStatus(403)
         }

         const existingUser = await getUserBySessionToken(sessionToken)
         if(!existingUser)
         {
            return res.sendStatus(403)
         }

         merge(req, {identity:existingUser })

         return next()
    }catch(error){
      console.log(error)
      return res.sendStatus(403)
    }
}
