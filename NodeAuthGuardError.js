module.exports = class NodeAuthGuardError extends Error {

    constructor(msg, status) {
        super(msg);
        this.name = 'NodeAuthGuardError';
        this.message = msg;
        this.msg = msg;
        this.status = status;
        Error.captureStackTrace(this.constructor, this);
    }
};