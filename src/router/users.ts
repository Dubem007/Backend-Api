import express from 'express'
import { getAllUsers,deleteUser } from '../controllers/users'
import  { isAuthenticated, isOwner } from '../middleware/index'

export default (router: express.Router)=>{
 router.get('/users', isAuthenticated, getAllUsers)
 router.delete('/users/:id', isAuthenticated, isOwner, deleteUser)
}