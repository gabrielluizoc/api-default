let mysql = require('mysql');

let pool  = mysql.createPool({
    "host"     : "DATABASE_HOST",
    "user"     : "DATABASE_USER",
    "password" : "DATABASE_PASSWORD",
    "database" : "DATABASE",
    "port"     : 3306
});

module.exports = pool;