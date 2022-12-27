import _ from 'lodash';
import micromatch from 'micromatch';

export const permissions = ['account.basic', 'account.email'];

export const mergePermissions = (...permissions: Array<Array<string>>): Array<string> => {
    return _.union(...permissions);
};

export const checkPermissions = (has: Array<string>, required: Array<string>): boolean => {
    if (required.includes('*')) return _.difference(micromatch(permissions, required), has).length === 0;
    else return micromatch(has, required).some((x: string) => has.includes(x));
};
