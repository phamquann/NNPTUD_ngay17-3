var express = require("express");
var router = express.Router();
let userController = require('../controllers/users')
let { RegisterValidator, validationResult } = require('../utils/validatorHandler')
let { CheckLogin } = require('../utils/authHandler')
let jwt = require('jsonwebtoken')
let fs = require('fs')

router.post('/register', RegisterValidator, validationResult, async function (req, res, next) {
    try {
        let newItem = await userController.CreateAnUser(
            req.body.username, req.body.password, req.body.email,
            "69af870aaa71c433fa8dda8e"
        )
        res.send(newItem);
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
})
router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let result = await userController.FindUserByUsername(username);
        if (!result) {
            res.status(403).send("sai thong tin dang nhap");
            return;
        }
        if (result.lockTime > Date.now()) {
            res.status(404).send("ban dang bi ban");
            return;
        }
        result = await userController.CompareLogin(result, password);
        if (!result) {
            res.status(403).send("sai thong tin dang nhap");
            return;
        }
        let privateKey = fs.readFileSync('private.pem');
        let token = jwt.sign({
            id:result._id
        }, privateKey,{
            expiresIn:'1d',
            algorithm:'RS256'
        })
        res.cookie("LOGIN_NNPTUD_S3", token, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: true
        })
        res.send(token)

    } catch (err) {
        res.status(400).send({ message: err.message });
    }
})
router.get('/me', CheckLogin, function (req, res, next) {
    let user = req.user;
    res.send(user)
})
router.post('/logout', CheckLogin, function (req, res, next) {
    res.cookie("LOGIN_NNPTUD_S3", "", {
        maxAge: 0,
        httpOnly: true
    })
    res.send("da logout ")
})

router.post('/changepassword', CheckLogin, async function (req, res, next) {
    try {
        let user = req.user;
        let { oldpassword, newpassword } = req.body;
        
        if (!newpassword) {
            return res.status(400).send("newpassword là bắt buộc");
        }
        
        // Validate newpassword structure (e.g. length >= 6, contain uppercase, number, etc.)
        let regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!regex.test(newpassword)) {
            return res.status(400).send("newpassword chưa đủ mạnh (8+ ký tự, in hoa, in thường, số, ký tự đặc biệt)");
        }
        
        // Kiểm tra oldpassword bằng cách sử dụng CompareLogin
        // Vì CompareLogin có đếm loginCount nên xử lý tương tự login
        let bcrypt = require('bcrypt'); // Để check password mà không tăng login count sai
        if (!bcrypt.compareSync(oldpassword, user.password)) {
            return res.status(403).send("Mật khẩu cũ không đúng");
        }
        
        user.password = newpassword;
        await user.save();
        
        res.send("Đổi mật khẩu thành công");
    } catch (err) {
        res.status(400).send({ message: err.message });
    }
});

module.exports = router;