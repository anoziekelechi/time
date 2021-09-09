
window.onload = greetUsers;
function greetUsers() {
var time = new Date().getHours();
if (time >= 12 && time <= 15){
 document.getElementById("demo").innerHTML = "Good Afternoon";
}
else if(time >= 16 && time <= 19){
document.getElementById("demo").innerHTML = "Good Evening guest";
}
else if(time >= 20 && time <= 22){
document.getElementById("demo").innerHTML = "Good Night guest";
}

else {
document.getElementById("demo").innerHTML = "Good Morning guest";
}
}

