exports.auth = (req, res) => {
    res.status(200).json({
        message : 'User logged in'
    });
}