export function getAvatarCode(date: Date) {
    return ~~((date.getTime() / (date.getDay() + date.getMonth())) * date.getSeconds() - date.getFullYear());
}
