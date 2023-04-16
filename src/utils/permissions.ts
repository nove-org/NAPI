import _ from 'lodash';
import micromatch from 'micromatch';

export const ALL_PERMISSIONS = ['account.read.basic', 'account.read.email', 'account.write.basic', 'account.write.email', 'account.write.avatar'] as const;
export type TPermission = typeof ALL_PERMISSIONS[number];

export const mergePermissions = (...permissions: Array<Array<TPermission>>): Array<TPermission> => {
    return _.union(...permissions);
};

export function checkPermission(userPermissions: TPermission[], permissionToCheck: TPermission) {
    return !micromatch.match(ALL_PERMISSIONS, permissionToCheck).some((permission) => {
        return !userPermissions.some((userPermission) => {
            return micromatch.isMatch(permission, userPermission);
        });
    });
}

export function checkPermissions(userPermissions: TPermission[], permissionsToCheck: TPermission[]) {
    return permissionsToCheck.every((permission) => checkPermission(userPermissions, permission));
}
