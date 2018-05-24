/*
 * Wrapper for RSA 
 *
 **/

const cryptico = require('js-cryptico')
// const BigInteger = require('cryptico/src/jsbn.js')

const parseBigInt = (a,b)=>{
    if(a.substr(0,2) == "0x"){
        a = a.substr(2)
    }
    const rsaparse = new cryptico.RSAKey()
    return rsaparse.parseInt(a,b)
}

module.exports = class DCRSa {
    constructor(publicExponent = "10001", passphrase = "default"){
        Math.seedrandom(passphrase);
        this.RSA = new cryptico.RSAKey();
        this.publicExponent = publicExponent;
    }
    
    // Method for creation private RSA keys for sign (for Bankroller)
    generate(long = 2048){
        this.RSA.generate(long, this.publicExponent)
    }

    generateByPQ(p, q){
        this.RSA.generateByPQ(p, q, this.publicExponent)
    }

    // Method for creation public RSA keys for verify (for Player)
    create(modulus){
      this.RSA.setPublic(modulus, this.publicExponent)
    }

    // Verification rawMsg and Signed msg
    verify(message, signedMessage){
       let msg        = parseBigInt(message, 16);
       let sigMsg     = parseBigInt(signedMessage, 16);
       msg            = msg.mod(this.RSA.n);
       let newMessage = this.RSA.doPublic(sigMsg);
       return(newMessage.equals(msg));
    }
    // Sign rawMsg
    signHash(message){
        let msg = parseBigInt(message, 16);
        msg = msg.mod(this.RSA.n);
        return this.RSA.doPrivate(msg);
    }
}
