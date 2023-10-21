export function getAvatarCode(date: Date) {
    return Math.abs(~~((date.getTime() / (date.getDay() + date.getMonth())) * date.getSeconds() - date.getFullYear()));
}
