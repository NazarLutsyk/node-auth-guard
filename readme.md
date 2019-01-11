#Node Auth Guard
###Small and flexible library for authorization

````javascript
let express = require('express');
let authGuard = require('node-auth-guard');
let app = express();

app.use((req, res, next) => {

    //add manually some principal
    req.some = {
        path: {
            to: {
                principal: {
                    name: 'some name',
                    surname: 'some surname',

                    //field with roles of principal
                    roles: ['USER', 'ADMIN']
                    //or you can specify only one => role: 'ADMIN'
                }
            }
        }
    };
    next();
});

//initialize authorization
app.use(authGuard.initialize({

    //path in the req object which will be indicate principal field
    //default value "user"
    principalPath: 'some.path.to.principal',

    //name of field which will be indicate principal roles field
    //default value "roles"
    rolesField: 'roles'
    
}));

//route opened for users that have "ADMIN" or "USER" roles
app.get('/', authGuard.roles('USER', 'ADMIN'), (req, res, next) => {
    res.end('Hello!');
});

//route opened for users that have a name "Rick"
app.get('/',
    authGuard.rule(
        (req, res, next) => {
        
            //do some checks
            //if all ok you may call next() otherwise send error
            if (req.some.path.to.principal.name === 'Rick') {
                return next()
            }else {
                return next(new Error('Forbidden!'));
            }

        }
    ),
    (req, res, next) => {
        res.end('Hello!');
    }
);

//route opened for users that have "ADMIN" or "SUPER_ADMIN" roles
//or
//they performing the rule
app.get('/',
    authGuard.rule(
        (req, res, next) => {/*do some checks...*/},
       
        //you can specify roles for which rule will not be executed
        'ADMIN',
        'SUPER_ADMIN'
    ),
    (req, res, next) => {
        res.end('Hello!');
    }
);

app.listen(3000);
````
#### Standart rules
````javascript
    //only for authenticated users
    app.get(
        '/', 
        authGuard.rules.isAuthenticated,     
        (req, res, next) => {
            res.end('Hello!');
        }
    );

    //only for NOT authenticated users
    app.get(
        '/', 
        authGuard.rules.isNotAuthenticated,     
        (req, res, next) => {
            res.end('Hello!');
        }
    );
````
