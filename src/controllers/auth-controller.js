const mysql = require('../database');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authConfig = require('../config/auth.json');
const encrypt = require('../utils/encrypt');
const crypto =  require('crypto');

exports.verifyEmail = (req, res) => {
    const { email } = req.body;
    mysql.getConnection((error, conn) => {       
        conn.query(
            `SELECT users.email
                FROM users
                    WHERE users.email = ?;
            `,
            [ email ],
            (error, result, field) => {
                conn.release();
                
                if(error) 
                    res.status(500).json({
                        error : "Ops...an internal error has occurred, please try again."
                    });
                
                if(result.length > 0)
                    res.status(200).json({
                        isRegistered: true,
                        message : "This email has already been registered, try another..."
                    });
                else
                    res.status(200).json({
                        isRegistered: false
                    });                                                           
            }
        );
    });
}

exports.verifyToken = (req, res) => {
    const authHeader  = req.headers.authorization;

    if(!authHeader)
        res.status(401).json({
            error : 'No token provided'
        });
    
    const parts = authHeader.split(' ');    

    if(!parts.length === 2)
        res.status(401).json({
            error : 'Token error'
        });
    
    
    const [ scheme, token ] = parts;    

    if(!/^Bearer$/i.test(scheme))
        res.status(401).json({
            error : 'Token malformatted'
        });
    
    jwt.verify(token, authConfig.secret, (error, decoded) =>{
        if(error)
            res.status(401).json({
                error : error
            });
        
        req.userId = decoded.id; 
        res.status(200).json({
            userId : decoded.id
        });
    });
};

exports.register = async (req, res) => {
    let user = req.body;    
    try {
        user.password ? user.password = await encrypt.generateHash(user.password, 10) : user.password = crypto.randomBytes(80).toString('hex');
        mysql.getConnection((error, conn) => {
            conn.query(
                `INSERT INTO 
                    users(
                        id_type_user,
                        first_name,
                        last_name,                        
                        email,
                        password,                       
                    )
                    VALUES (?, ?, ?, ?, ?);
                    `,
                    [
                        user.idTypeUser,
                        user.firsName,
                        user.lastName,                        
                        user.email,
                        user.password                        
                    ],                   
                    (error, result, field) => {
                        conn.release();
                        
                        if (error) 
                            res.status(500).json({
                                error: "Ops...an internal error has occurred, please try again."
                            });
                        
                        user.password = undefined;
                        res.status(201).send({ user });
                    }
            );
        });
    } catch (error) {
        res.status(400).json({
            error : "Ops...an internal error has occurred, please try again."
        })
    }
}

exports.authenticate = async (req,res) => {
    const { email, password } = req.body;
    mysql.getConnection((error,conn) => {
        conn.query(
            `SELECT 
                users.email, 
                users.password
            FROM users
                WHERE
                    users.email = ?;
            `,email,
            (error, result, field) => {
                conn.release();
                
                if(error)
                    res.status(400).json({
                        error:error
                    });
                
                if (!result.length > 0)
                    res.status(400).json({
                        message: "Invalid email or password!"
                    });        
                
                    if (result.length >0)    
                    bcrypt.compare(password, result[0].password, 
                        (error, result)=>{
                            
                            if(error)
                                res.status(400).json({
                                    error:error
                                });
                            
                            if(result){
                                mysql.getConnection((error, conn) => {
                                    conn.query(
                                        `SELECT 
                                            users.id_user,
                                            users.id_type_user                                            
                                        FROM users
                                            WHERE
                                                users.email = ?;
                                        `,email,
                                        (error,result,field) =>{
                                            conn.release();
                                            
                                            if(error)
                                                res.status(400).json({
                                                    error:error
                                                });
                                            
                                            const token = jwt.sign({ id: result[0].id_user },authConfig.secret,{
                                                expiresIn: 86400
                                            });
                                            
                                            res.status(200).json({
                                                user : result[0],
                                                token : token
                                            });
                                        }
                                    );
                                })
                            } else {
                                res.status(401).json({
                                    message: "Invalid email or password!"
                                });
                            }
                        });
            }   
        );
    });
}