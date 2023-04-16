/**
 * @description: Overwrite some properties of T with those in type R
 */
export type Modify<T, R> = Omit<T, keyof R> & R;
