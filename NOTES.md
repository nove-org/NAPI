-   `GET /v1/users/login` HAS to be opened as a new window to close and redirect properly, example code below

    ```js
    function createPopupWin(pageURL, pageTitle, popupWinWidth, popupWinHeight) {
        var left = (screen.width - popupWinWidth) / 2;
        var top = (screen.height - popupWinHeight) / 4;

        var myWindow = window.open(pageURL, pageTitle, 'resizable=yes, width=' + popupWinWidth + ', height=' + popupWinHeight + ', top=' + top + ', left=' + left);
    }
    ```
