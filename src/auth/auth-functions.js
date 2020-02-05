const jwt = require('jsonwebtoken');
const {
    JWT_TOKEN_EXPIRES,
    HASURA_GRAPHQL_JWT_SECRET,
    AUTH_PRIVATE_KEY,
    STORAGE_JWT_SECRET,
    USER_FIELDS,
} = require('../config');

module.exports = {
    generateJwtToken: function (user) {

        let custom_claims = {};

        USER_FIELDS.forEach(user_field => {

            if (typeof user[user_field] === undefined || user[user_field] === null) {
                return null;
            }

            custom_claims['x-hasura-' + user_field.replace('_', '-')] = user[user_field] && user[user_field].toString();
        });

        let default_role = '';
        const user_roles = user.user_roles.map(role => {
            if (role.default) {
                default_role = role.role
            }
            return role.role;
        });

        // if (!user_roles.includes(user.default_role)) {
        //     user_roles.push(user.default_role);
        // }

        return jwt.sign({
            'https://hasura.io/jwt/claims': {
                'x-hasura-allowed-roles': user_roles,
                'x-hasura-default-role': default_role,
                'x-hasura-user-id': user.id.toString(),
                ...custom_claims,
            },
        }, AUTH_PRIVATE_KEY, {
            subject: user.id.toString(),
            algorithm: 'RS256',
            expiresIn: `${JWT_TOKEN_EXPIRES}m`,
        });
    },
};