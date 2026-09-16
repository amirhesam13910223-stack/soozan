/* ─── Soozan × Eitaa Bridge (فاز ۳ / U5) ─── */
window.SoozanEitaa = (function(){
  "use strict";
  var ua = navigator.userAgent || "";
  function sdk(){
    return window.EitaaWebApp || window.eitaaWebApp || window.Eitaa || window.eitaa || null;
  }
  var isEitaa = /Eitaa|EitaaBot/i.test(ua) || !!sdk();

  /* اشتراک لینک با fallback سه‌لایه: SDK ایتا → Web Share → کلیپ‌بورد */
  async function share(url, title){
    var s = sdk();
    if(s){
      try{
        if(typeof s.shareURL === "function"){ s.shareURL(url); return "eitaa"; }
        if(typeof s.share === "function"){ s.share({url:url, title:title}); return "eitaa"; }
        if(typeof s.openLink === "function"){ s.openLink(url); return "eitaa"; }
      }catch(e){}
    }
    if(navigator.share){
      try{ await navigator.share({url:url, title:title||""}); return "webshare"; }
      catch(e){ if(e && e.name === "AbortError") return "canceled"; }
    }
    try{ await navigator.clipboard.writeText(url); return "clipboard"; }
    catch(e){ return "fail"; }
  }

  /* stub برای فاز ۷: ورود با ایتا (hash validation بعداً) */
  function loginPayload(){
    var s = sdk();
    if(s && s.initData) return s.initData;
    return null;
  }

  return { isEitaa: isEitaa, share: share, sdk: sdk, loginPayload: loginPayload };
})();
