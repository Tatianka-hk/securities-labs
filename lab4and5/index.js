
const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const port = 3000;
const fs = require('fs');
const axios = require('axios');  //he añadido en 4
const qs = require('qs');//he añadido en 4
const jwksClient = require('jwks-rsa');
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
require('dotenv').config(); 
const SESSION_KEY = 'Authorization';

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());

            // console.log(this.#sessions);
        } catch(e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8');
    }

    set(key, value) {
        if (!value) {
            value = {};
        }
        this.#sessions[key] = value;
        this.#storeSessions();
    }

    get(key) {
        return this.#sessions[key];
    }

    init(res) {
        // const sessionId = jwt.sign({}, 'tt99'); 
        const sessionId = uuid.v4();
        this.set(sessionId);

        return sessionId;
    }

    destroy(req, res) {
        const sessionId = req.sessionId;
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }
}

const sessions = new Session();

app.use((req, res, next) => {
    let currentSession = {};
    let sessionId = req.get(SESSION_KEY);

    if (sessionId) {
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init(res);
        }
    } else {
        sessionId = sessions.init(res);
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(req, () => {
        const currentSession = req.session;
        const sessionId = req.sessionId;
        sessions.set(sessionId, currentSession);
    });

    next();
});
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});
app.get('/', (req, res) => {
    if (req.session.username) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

const users = [
    {
        login: 'tjdshf987y@gmail.com',
        password: 'string1234567!',
        username: 'tjdshf987y@gmail.com',
    },
    {
        login: 'Login1',
        password: 'Password1',
        username: 'Username1',
    }
]
// Create a JWKS client instance
const jwksClientInstance = jwksClient({
    jwksUri: 'https://dev-y6vlf8ogogmzlyec.us.auth0.com/.well-known/jwks.json',
});

// Function to get the public key from JWKS
const getKey = (header, callback) => {
    jwksClientInstance.getSigningKey(header.kid, (err, key) => {
        const signingKey = key.publicKey || key.rsaPublicKey;
        callback(null, signingKey);
    });
};

// Verify JWT token
const verifyToken = (token) => {
    jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
        if (err) {
            console.error('Error verifying token:', err.message);
            return false;
        }
        console.log('Decoded Token:', decoded);
        return true;
    });
};

//he añadido en 4
app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;
    console.log(login, " '  ", password)

    const user = users.find((user) => {
        if (user.login == login && user.password == password) {
            console.log("true")
            return true;
        }
        return false;
    });
    console.log( "env    ",process.env.audience, ", ",process.env.client_id)

    if (user) {
        const data = {
            audience: process.env.audience,
            grant_type: 'password',
            client_id: process.env.client_id,
            client_secret:  process.env.client_secret,
            password: password,
            username: login,
            scope:'offline_access'
        };
        

        const headers = {
            'content-type': 'application/x-www-form-urlencoded',
        };

        try {
            const response = await axios.post('https://dev-y6vlf8ogogmzlyec.us.auth0.com/oauth/token', qs.stringify(data), { headers });
        
            if (response.data && response.data.access_token) {
                console.log(response.data)
                
                // const isTokenValid = verifyToken(response.data.access_token);
        
                // if (isTokenValid) {
                //     return json({ token: response.data.access_token });
                // } else {
                //     return  res.status(401).json({ error: 'Unauthorized' });
                // }
                res.json({ token: response.data.access_token });
            } else {
                console.error('Access token not found in the response');
                return res.status(500).json({ error: 'Internal Server Error' });
            }
        } catch (error) {
            console.error('Error getting token:', error.message);
        
            if (error.response) {
                console.error('Response Status:', error.response.status);
                console.error('Response Data:', error.response.data);
        
                return res.status(error.response.status).json({ error: 'Internal Server Error' });
            } else {
                console.error('Error Object:', error);
        
                return res.status(500).json({ error: 'Internal Server Error' });
            }
        }
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
});
//he añadido en 4
app.get('/refresh', async (req, res) => {
    const data = {
        refresh_token: 'eP2mW0DC5embJ70t5TAyPxvgXhIaI6aX9wVnK8RQv3EIY',
        grant_type: 'refresh_token',
        client_id: process.env.client_id,
        client_secret:  process.env.client_secret,
    };

    const headers = {
        'content-type': 'application/x-www-form-urlencoded',
    };
    try {
        const response = await axios.post('https://dev-y6vlf8ogogmzlyec.us.auth0.com/oauth/token', qs.stringify(data), { headers });
    
        if (response.data) {
            console.log(response.data)
            res.json({ token: response.data.access_token });
        } else {
            console.error('Access token not found in the response');
            res.status(500).json({ error: 'Internal Server Error' });
        }
    } catch (error) {
        console.error('Error getting token:', error.message);
    
        if (error.response) {
            console.error('Response Status:', error.response.status);
            console.error('Response Data:', error.response.data);
    
            res.status(error.response.status).json({ error: 'Internal Server Error' });
        } else {
            console.error('Error Object:', error);
    
            res.status(500).json({ error: 'Internal Server Error' });
        }
    }

   
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
