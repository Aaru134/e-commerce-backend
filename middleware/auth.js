import jwt from 'jsonwebtoken';

const authUser = async (req, res, next) => {
    // Extract token from Authorization header
    const token = req.headers.token;
    console.log(token);

    if (!token) {
        return res.status(401).json({ success: false, message: 'Not Authorized. Please log in again.' });
    }

    try {
        // Verify and decode the token
        const token_decode = jwt.verify(token, process.env.JWT_SECRET);
        req.body.userId = token_decode.id; // Add userId to request body
        next(); // Proceed to the next middleware
    } catch (error) {
        console.error("JWT Verification Error:", error);
        res.status(401).json({ success: false, message: 'Invalid or Expired Token' });
    }
};

export default authUser;


/*import jwt from 'jsonwebtoken'

const authUser = async (req, res, next) => {

    const { token } = req.headers;

    if (!token) {
        return res.json({ success: false, message: 'Not Authorized Login Again' });
    }

    try {

        const token_decode = jwt.verify(token, process.env.jwt_SECRET)
        req.body.userId = token_decode.id
        next()

    } catch (error) {
        console.log(error)
        res.json({ success: false, message: error.message })
    }

}

export default authUser;*/

