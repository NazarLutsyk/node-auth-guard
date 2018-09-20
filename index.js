let NodeAuthGuardError = require("./NodeAuthGuardError");

let libConfig = {
    principalPath: 'user',
    rolesField: 'roles'
};

let state = {
    principal: null,
    principalRoles: null
};

let lib = {};

function isAllowed(allowed, userRoles) {
    userRoles = typeof userRoles === 'string' ? [userRoles] : userRoles;

    if (allowed && userRoles && allowed.length > 0 && userRoles.length > 0) {
        for (let role of userRoles) {
            if (allowed.indexOf(role) !== -1) {
                return true;
            }
        }
    }
    return false;
}

lib.initialize = (config = {principalPath: '', rolesField: ''}) => {
    libConfig.principalPath =
        (typeof config.principalPath === 'string' && config.principalPath.length > 0)
            ? config.principalPath
            : libConfig.principalPath;
    libConfig.rolesField =
        (typeof config.rolesField === 'string' && config.rolesField.length > 0)
            ? config.rolesField
            : libConfig.rolesField;
    return (req, res, next) => {
        let principalPathSplitted = config.principalPath.split('.');
        let principalFind = req;
        for (let i = 0; i < principalPathSplitted.length; i++) {
            const pathElement = principalPathSplitted[i];
            principalFind = principalFind[pathElement];
        }
        if (principalFind) {
            state.principal = principalFind;
            let roles = state.principal[config.rolesField];
            state.principalRoles = Array.isArray(roles) ? roles : [roles];
            state.principal[config.rolesField] = state.principalRoles;
        }
        console.log(state);
        next();
    }
};


lib.roles = function (...roles) {
    return (req, res, next) => {
        if (!roles || roles.length <= 0) {
            return next(new NodeAuthGuardError('Please specify allowed roles', 500));
        }

        for (let role of roles) {
            if (typeof role !== 'string') {
                return next(new NodeAuthGuardError('Name of role must be a string!', 500));
            }
        }

        if (state.principal && isAllowed(roles, state.principalRoles)) {
            return next();
        }

        return next(new NodeAuthGuardError('Forbidden', 403));
    };
};

lib.rule = function (rule, ...exclusionRoles) {
    return (req, res, next) => {
        if (exclusionRoles && state.principal && isAllowed(exclusionRoles, state.principalRoles)) {
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

module.exports = lib;