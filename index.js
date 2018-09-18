let NodeAuthGuardError = require("./NodeAuthGuardError");

function isAllowed(allowed, userRoles) {
    if (allowed && userRoles && allowed.length > 0 && userRoles.length > 0) {
        for (let role of userRoles) {
            if (allowed.indexOf(role) !== -1) {
                return true;
            }
        }
    }
    return false;
}

exports.roles = function (...roles) {
    return (req, res, next) => {
        if (!roles || roles.length <= 0) {
            return next(new NodeAuthGuardError('Please specify allowed roles', 500));
        }

        for (let role of roles) {
            if (typeof role !== 'string') {
                return next(new NodeAuthGuardError('Name of role must be a string!', 500));
            }
        }

        if (req.user && isAllowed(roles, req.user.roles)) {
            return next();
        }

        return next(new NodeAuthGuardError('Forbidden', 403));
    };
};

exports.rule = function (rule, ...exclusionRoles) {
    return (req, res, next) => {
        if (exclusionRoles && req.user &&isAllowed(exclusionRoles, req.user.roles)) {
            return next();
        } else {
            if (typeof rule !== 'function') {
                return next(new NodeAuthGuardError('Rule must be a function', 500));
            } else {
                return rule(req, res, next);
            }
        }
    }
};
