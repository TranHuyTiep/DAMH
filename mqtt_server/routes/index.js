var express = require('express');
var router = express.Router();
var mqtt = require('mqtt')

var client  = mqtt.connect('mqtt://test.mosquitto.org')

client.on('connect', function () {
    client.subscribe('reply')
})

/* GET home page. */
router.get('/', function(req, res, next) {
    res.render('index', { title: 'Express' });
});

module.exports = router;
