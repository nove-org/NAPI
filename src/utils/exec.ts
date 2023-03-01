import { promisify } from 'node:util';
import { exec as callbackExec } from 'child_process';
export default promisify(callbackExec);
