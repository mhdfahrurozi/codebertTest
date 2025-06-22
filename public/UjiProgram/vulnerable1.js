// Open Redirect: tidak validasi URL tujuan
const redirectTo = new URLSearchParams(window.location.search).get("redirect"); 
if (redirectTo) {                                                               
    window.location.href = redirectTo;                                          
}

// CSRF-like request: tidak pakai CSRF token
function updateProfile() {                                                     
    fetch("/update-profile", {                                                 
        method: "POST",                                                        
        credentials: "include"                                                 
    });                                                                         
}

// Logging informasi sensitif ke konsol
const credentials = { user: "admin", pass: "123456" };                         
console.log("User creds:", credentials);                                       
