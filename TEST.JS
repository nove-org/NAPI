const micromatch = require('micromatch');

const userPermissions = ['user.read', 'user.write.email'];
const permissionToCheck = 'user.write.*';
const allPermissions = ['user.read', 'user.write.email', 'user.write.name', 'user.delete', 'user.create'];

function hasPermission(userPermissions, permissionToCheck) {
    return !micromatch.match(allPermissions, permissionToCheck).some((permission) => {
        return !userPermissions.some((userPermission) => {
            return micromatch.isMatch(permission, userPermission);
        });
    });
}

console.log(hasPermission(userPermissions, permissionToCheck)); // true
