'use strict';

var express = require('express');
var routes = require('./app/routes/index.js');
var mongoose = require('mongoose');
var session = require('express-session');
var bodyParser = require('body-parser');

var app = express();
var server = require('http').Server(app);
const io = require('socket.io')(server);
require('dotenv').load();


mongoose.connect(process.env.MONGO_URI);
mongoose.Promise = global.Promise;

app.use('/controllers', express.static(process.cwd() + '/app/controllers'));
app.use('/public', express.static(process.cwd() + '/public'));
app.use('/common', express.static(process.cwd() + '/app/common'));
app.use(bodyParser.urlencoded({extended:false}));
app.set('view engine','ejs');





var port = process.env.PORT || 3000;
server.listen(port,  function () {
	console.log('Node.js listening on port ' + port + '...');
});

io.on('connection',function(socket){
	
	socket.emit('greeting',{hi:'name'});
	console.log('------------------- io connected');

	socket.on("disconnect", () => console.log("Client disconnected"));
});