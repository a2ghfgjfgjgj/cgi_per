function enableMouseEvent() {
    let e = document.getElementsByTagName("body")[0];
    e.style.pointerEvents = "all";
}

function disableMouseEvent() {
    let e = document.getElementsByTagName("body")[0];
    e.style.pointerEvents = "none";
}

function showErrorEnterToSite(show = true) {
    if (!show) {
        let e=   document.getElementById("element-e-login");
        e.innerHTML = "";
    }
    else if (show) {
        let e=   document.getElementById("element-e-login");
        e.innerHTML = "Wrong Member ID / Password";
    }
}

function showErrorUsername(show = true) {
    if (!show) {
        let e = document.getElementById("element-e-username");
        e.innerHTML = "";
    } else if (show) {
        let e =
            document.getElementById("element-e-username");
        e.innerHTML = "The field is filled in incorrectly";
    }
}

function showErrorPassword(show = true) {
    if (!show) {
        let e = document.getElementById("element-e-password");
        e.innerHTML = "";
    } else if (show) {
        let e = document.getElementById("element-e-password");
        e.innerHTML = "The field is filled in incorrectly";
    }
}

function showErrorForOTP(show = true) {
    if (!show) {
        let e = document.getElementById("element-e-otp");
        e.innerHTML = "";
    } else if (show) {
        let e = document.getElementById("element-e-otp");
        e.innerHTML = "Please confirm your Identity";
    }
}


function showErrorForCaptcha(show = true) {
    if (!show) {
        let e = document.getElementById("element-e-turing");
        e.innerHTML = "";
    } else if (show) {
        let e = document.getElementById("element-e-turing");
        e.innerHTML = "Wrong turing";
    }
}







