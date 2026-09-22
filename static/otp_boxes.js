(function(){
  var boxes = document.querySelectorAll(".ob-box");
  var hidden = document.getElementById("ob-hidden");
  if(!boxes.length || !hidden) return;
  function sync(){ hidden.value = Array.prototype.map.call(boxes, function(b){ return b.value; }).join(""); }
  boxes.forEach(function(b, i){
    b.addEventListener("input", function(){
      b.value = b.value.replace(/\D/g, "").slice(-1);
      sync();
      if(b.value && i < 5) boxes[i+1].focus();
    });
    b.addEventListener("keydown", function(e){
      if(e.key === "Backspace" && !b.value && i > 0) boxes[i-1].focus();
      sync();
    });
    b.addEventListener("paste", function(e){
      e.preventDefault();
      var d = ((e.clipboardData || window.clipboardData).getData("text") || "").replace(/\D/g, "").slice(0, 6);
      for(var j = 0; j < 6; j++){ boxes[j].value = d[j] || ""; }
      sync();
      if(d.length) boxes[Math.min(d.length, 5)].focus();
    });
  });
  sync();
})();
