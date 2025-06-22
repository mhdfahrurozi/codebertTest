// Race Condition: tidak ada locking saat update stok
let stock = 5;                                               
function buyItem() {                                         
    if (stock > 0) {                                         
        stock--;                                             
        console.log("Purchase successful");                  
    } else {                                                 
        console.log("Out of stock");                         
    }                                                        
}

// Resource leak: interval tidak pernah dibersihkan
setInterval(() => {                                          
    console.log("Ping server");                              
}, 1000);                                                    

// UI/UX issue: tidak beri feedback saat loading
function submitForm() {                                      
    fetch("/submit");                                        
}                                                            
