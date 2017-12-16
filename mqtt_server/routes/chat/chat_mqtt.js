var express = require('express')
var router = express.Router();

router.route('/chat')
    .get(function (req,res,next) {
        res.render('chat')
    });

module.exports =  router
