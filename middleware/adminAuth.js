import jwt from 'jsonwebtoken';

const adminAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer')) {
            return res.json({ success: false, message: "Not Authorized, Login Again" });
        }
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded.email !== process.env.ADMIN_EMAIL || decoded.password !== process.env.ADMIN_PASSWORD) {
            return res.json({ success: false, message: "Not Authorized, Login Again" });
        }
        next();
    } catch (error) {
        console.log(error);
        res.json({ success: false, message: error.message });
    }
};

export default adminAuth;





/*import jwt from 'jsonwebtoken';

const adminAuth = async (req, res, next) => {
    try {
        const { token } = req.headers;

        if (!token) {
            return res.status(401).json({ success: false, message: "Not Authorized. Login Again." });
        }

        const token_decode = jwt.verify(token, process.env.JWT_SECRET);
        console.log(token_decode);

        if (token_decode.email !== process.env.ADMIN_EMAIL) {
            console.log("Unauthorized attempt");
            return res.status(403).json({ success: false, message: "You do not have admin privileges." });
        }

        next(); // If the token is valid and the user is admin, proceed
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: "Server Error: " + error.message });
    }
};

export default adminAuth;
*/
