const express = require('express');
const router = express.Router();
const userController = require('../controllers/user-controller');
const authMiddleware = require('../middleware/auth-middleware');

router.use(authMiddleware);
router.get('/', userController.auth);

module.exports = app => app.use('/user', router);
