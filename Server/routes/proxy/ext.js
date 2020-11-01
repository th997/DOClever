var crypto = require('crypto');
var encoding = "utf8";

var aeskey, securekey

// 判断是否需要扩展条件
function isCond(req) {
    return req.headers["secure"];
}

// 预处理，示例
function preSet(req, opt) {
    if (isCond(req)) {
        // 初始化配置
        if (!(aeskey && securekey)) {
            let config = require("./config.json");
            aeskey = Buffer.from(config.aeskey, 'hex');
            securekey = config.securekey;
        }
        opt.headers['securekey'] = securekey;
        opt.headers['Accept-Encoding'] = 'none';
        if (!opt.headers['Content-Type']) {
            opt.headers['Content-Type'] = 'application/json; charset=utf-8'
        }
        console.log("req headers:", opt);
    }
}

function aesEncrypt(str) {
    let iv = Buffer.from(crypto.randomBytes(8), encoding)
    let cipher = crypto.createCipheriv('aes-128-gcm', aeskey, iv);
    cipher.setAutoPadding(true)
    return Buffer.concat([Buffer.from([iv.length]), iv, cipher.update(str, encoding), cipher.final(), cipher.getAuthTag()]).toString("hex")
}

function aesDecrypt(crypted) {
    crypted = Buffer.from(crypted, 'hex');
    let ivLen = crypted.readInt8(0);
    let iv = crypted.slice(1, ivLen + 1)
    let cipher = crypto.createDecipheriv('aes-128-gcm', aeskey, iv);
    let ret = cipher.update(crypted.slice(1 + ivLen), 'binary');
    return ret.slice(0, ret.length - aeskey.length).toString(encoding);
}

module.exports = {
    isCond,
    preSet,
    aesEncrypt,
    aesDecrypt,
}