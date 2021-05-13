const { Router } = require('express')
const router = new Router()

const bcryptjs = require('bcryptjs')
const saltRounds = 10 // SALTING

const User = require('../models/User.model')
const mongoose = require('mongoose');

//first rute
router.get('/signup', (req, res) => {
    res.render('auth/signup')
})

// router post
router.post('/signup', (req, res, next) => {
    console.log('The form data:', req.body)

    const { username, password } = req.body


    
    // VALIDACIONES
    if(!username || !password){
        res.render('auth/signup', {errorMessage: "Todos los campos son obligatorios. Uno no está lleno."})
        return
    }
    const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/ // VIGILA QUE TENGA 6 CARACTERES O MÁS. Pueden ser mayús, minus, números

    if(!regex.test(password)){
        res.status(500).render('auth/signup', {errorMessage: "El pass debe tener 6 caracter o más"})
    }


    // OPCIÓN A - PROCESO SÍNCRONO
    // const hashedPassword = bcryptjs.hashSync(password, 10);
    // console.log(`Password hash: ${hashedPassword}`);

    // OPCIÓN B - PROCESO ASÍNCRONO
    // PROCESO DE ENCRIPTAMIENTO
    bcryptjs
        // REVOLVENTE
        .genSalt(saltRounds)
        // HASHING (SINTESIS DEL PASSWORD A UN STRING CHIQUITO PARA BASE DE DATOS)
        .then(salt => bcryptjs.hash(password, salt))
        // INSERCIÓN EN BASE DE DATOS
        .then(hashedPassword => {
            console.log(`Password hash:: ${hashedPassword}`)
            return User.create({
                username,
                passwordHash: hashedPassword
            })
        })
        .then(userFromDB => {
            console.log("Usuario creado:", userFromDB)
            res.redirect('/userProfile')
            return
        })
        .catch(error => {
            console.log(error)
            if(error instanceof mongoose.Error.ValidationError){ // CAPTURAMOS EL ERROR DE MONGOOSE
                res.status(500).render('auth/signup', {errorMessage: error.message}) // PUEDEN CAMBIAR EL ERROR.MESSAGE POR UNO PERSONALIZADO
            } else if(error.code === 11000) {
                res.status(500).render('auth/signup', {errorMessage: "El usuario y/o el correo deben ser únicos."})
            }           
            else{
                console.log(error)
            }
    })
})

router.get('/userProfile', (req, res) => {
    res.render('users/userProfile',{user:req.session.currentUser}) 

})

router.get('/login', (req, res) => {
    res.render('auth/login')
})

router.post('/login', (req, res, next) => {
    console.log('SESSION =====> ', req.session);

    // 1. OBTENER LOS DATOS DEL FORMULARIO
    const {username, password} = req.body
        if(username === "" || password === ""){
            res.render('auth/login', {
                errorMessage: "Falta un campo por llenar"
            })
            return
        }

    // 2. ENCONTRAR AL USUARIO DENTRO DE LA BASE DE DATOS A TRAVÉS DEL EMAIL
        User.findOne({username})
            .then((usuarioEncontrado) => {
                // a. VALIDACIÓN - Si el usuario no fue encontrado en DB
                if(!usuarioEncontrado){
                    res.render('auth/login', {
                        errorMessage: "El Usuario no está registrado"
                    })
                    return
                } else if(bcryptjs.compareSync(password, usuarioEncontrado.passwordHash)){ // Si todo bien, vamos a verificar su password. Si esto sucede un true...
                    req.session.currentUser = usuarioEncontrado;
                    res.redirect('/userProfile');

                } else {
                    res.render('auth/login', {errorMessage: 'Password Incorrecto'} )
                }
            })
            .catch(e => next(e))    
})

router.get('/private', (req, res) => {
    const user = req.session.currentUser
    if(!user){
        res.redirect("/login")
    }
    res.render('private')
})

router.get('/main', (req, res) => {
    const user = req.session.currentUser
    if(!user){
        res.redirect("/login")
    }
    res.render('main')
})

module.exports= router;