const bcrypt = require('bcryptjs');

const helpears = {};

helpears.encryptPassword = async(password) => {
    const salt = bcrypt.genSaltSync(10);
    const newPassword = bcrypt.hashSync(password, salt);

    return newPassword;
}

helpears.matchPassword = async(password, savePassword) => {
    try {
        const resp = bcrypt.compareSync(password, savePassword);
        return resp;
    } catch (e) {
        console.log(e)
    }


}

module.exports = helpears;