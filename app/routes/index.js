'use strict';

var path = process.cwd();
var UserHandler = require('../handlers/userHandler.server');
const jwt = require('jsonwebtoken');
const url = require('url');
var PollHandler = require('../handlers/pollHandler.server');
module.exports = function (app, passport,io) {

 

    var userHandler = new UserHandler(passport);
    var pollHandler = new PollHandler();


    //  HOME - redirects to login if not logged in
    app.get('/', function(req, res, next) {
        passport.authenticate('jwt',{session:false}, function(err, user, info) {
        console.log(err+'--'+user+'--'+info);
          if (err) { return next(err); }
          if (!user) { 
            return res.status('400').sendFile(path + '/public/index.html'); }
        else{
            if(req.query.vote){
            return res.sendFile(path + '/public/user.html',{headers:{openVote:true}})
            }else{

                return res.sendFile(path + '/public/user.html')
            }
        }
        })(req, res, next);
    });

   

    app.get('/index', (req, res) => {
        res.sendFile(path + '/public/index.html');
    });


    app.route('/signup')
        .post((req, res) => {
            userHandler.addUser(req, res);
        });


  
    


    app.route('/logout')
        .get(function (req, res) {
            res.redirect('/');
        });


    app.route('/user')
        .get(passport.authenticate('jwt', { session: false }), (req,res) => {
            if (!req.user)
                res.redirect('/');
            else
                res.sendFile(path + '/public/user.html');
        });

    
    app.post('/auth/vote',passport.authenticate('jwt',{session:false}),(req,res)=>{
        if(!req.body.poll_id||!req.body.option)
            res.status(400).send('invalid request');
        pollHandler.update(req,res,io);
    })


    app.post('/auth/user/change_password',passport.authenticate('jwt',{session:false}),(req,res)=>{
        if(!req.body.current_password||!req.body.new_password)
        return res.status(400).send('Fill all the details');
        userHandler.changePassword(req,res);
    });
};