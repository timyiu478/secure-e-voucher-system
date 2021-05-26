function getCookie(cname) {
    var name = cname + "=";
    var ca = document.cookie.split(';');
    for(var i = 0; i < ca.length; i++) {
      var c = ca[i];
      while (c.charAt(0) == ' ') {
        c = c.substring(1);
      }
      if (c.indexOf(name) == 0) {
        return c.substring(name.length, c.length);
      }
    }
    return "";
}

  

function rsaEncryt(message){
    var rsa = new RSAKey();
    const public_exponent = "10001";
    const public_modulus = "bf1c21d505bb0785eaa5671d6081d011e9cacfe08b18dd344e55557629d3aaf1015d26b7f47f1ba1e6e5244e019714434f6cd2157aef2544c52589c226fcbaace1fe08a50ca9d47a168f52fcde8b4a3e3952a3139b52126b254a0d0513bdfbed2474f07f7217b3ec4d6f04e4dcd771ea9ac28f38087bf03eaab51baa5469a92f06b8dba41d7b324a0ee6f62f117520b5ab6fd37d6fefc0f85d4ee4eb6252db95fe0e37161551613a852a5b82775ee560f1df88ac4fbec21955fabea7f622bb89c6e8cfc2bb8f1640ecaf5192739545d069816ffb54a9f06261ecc62e679432eb28af6340bc7f8a96c4b547f62013597bcc2deb8c770bd5e38e7aff125dd33403";
    rsa.setPublic(public_modulus, public_exponent);
    var res = rsa.encrypt(message);
    return linebrk(res,64);
}