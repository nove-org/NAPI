export default class ObjectHelper {
    public static getValueByStringPath(obj: any, path: string, delim = '.') {
        const splittedPath = path.split(delim);
        let i = 0;
        let currentObj = obj;

        if (!path) return obj;

        for (const pathPart of splittedPath) {
            if (!currentObj.hasOwnProperty(pathPart)) return null;
            if (i + 1 == splittedPath.length) return currentObj[pathPart];
            else currentObj = currentObj[pathPart];

            i++;
        }
    }
}
