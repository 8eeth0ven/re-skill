# Java Layer Hook: Crypto and Self-Dump

> Topics: crypto (Cipher/Base64/the all-in-one self-dump kit) + hooking packed apps (classLoader)

## 5. Crypto

### 5.1 Cipher (init / doFinal)

```javascript
var Cipher = Java.use("javax.crypto.Cipher");

// 钩取 doFinal
Cipher.doFinal.overload("[B").implementation = function (data) {
    var mode = this.getAlgorithm();
    console.log("Cipher mode: " + mode);

    var inputString = byteArrayToBase64(data);
    console.log("Input data (Base64): " + inputString);

    var result = this.doFinal(data);
    var outputString = byteArrayToBase64(result);
    console.log("Encrypted/Decrypted output (Base64): " + outputString);

    return result;
};

// 钩取 init 方法
Cipher.init.overload('int', 'java.security.Key').implementation = function (opmode, key) {
    console.log("Cipher initialized!");
    console.log("Operation mode: " + opmode);
    console.log("Key: " + byteArrayToBase64(key.getEncoded()));
    return this.init(opmode, key);
};

Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode, key, spec) {
    console.log("Cipher initialized with params!");
    console.log("Operation mode: " + opmode);
    console.log("Key: " + byteArrayToBase64(key.getEncoded()));
    console.log("IV or params: " + spec);
    return this.init(opmode, key, spec);
};

function byteArrayToBase64(byteArray) {
    var Base64 = Java.use('android.util.Base64');
    return Base64.encodeToString(Java.array('byte', byteArray), 0); // 0 = DEFAULT
}
```

### 5.2 Base64

```javascript
var base64 = Java.use("android.util.Base64");
base64.encodeToString.overload('[B', 'int').implementation = function (a, b) {
    console.log("base64.encodeToString: ", JSON.stringify(a));
    var result = this.encodeToString(a, b);
    console.log("base64.encodeToString result: ", result)
    return result;
}
```

### 5.3 The all-in-one crypto self-dump kit (MessageDigest / Mac / Cipher / Signature)

When to use: dump, in one pass, the inputs, keys, IVs, and outputs of every digest/signature/symmetric-encryption call in the app (in Base64/Hex/Utf8 formats), with a stack-trace toggle. Ready to use as-is; no need to hand-write it again.

```javascript
const config = {
    showStacks: false,
    showDivider: true,
  }
  Java.perform(function () {
    // console.log('frida 已启动');
    function showStacks(name = '') {
      if (config.showStacks) {
        console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Throwable').$new(name)))
      }
    }
  
    function showDivider(name = '') {
      if (config.showDivider) {
        console.log(`==============================${name}==============================`)
      }
    }
  
    function showArguments() {
      console.log('arguments: ', ...arguments)
    }
  
    const ByteString = Java.use('com.android.okhttp.okio.ByteString')
    const Encode = {
      toBase64(tag, data) {
        console.log(tag + ' Base64: ', ByteString.of(data).base64())
        // console.log(tag + ' Base64: ', bytesToBase64(data));
      },
      toHex(tag, data) {
        console.log(tag + ' Hex: ', ByteString.of(data).hex())
        // console.log(tag + ' Hex: ', bytesToHex(data));
      },
      toUtf8(tag, data) {
        console.log(tag + ' Utf8: ', ByteString.of(data).utf8())
        // console.log(tag + ' Utf8: ', bytesToString(data));
      },
      toAll(tag, data) {
        Encode.toUtf8(tag, data)
        Encode.toHex(tag, data)
        Encode.toBase64(tag, data)
      },
      toResult(tag, data) {
        Encode.toHex(tag, data)
        Encode.toBase64(tag, data)
      },
    }
  
    const MessageDigest = Java.use('java.security.MessageDigest')
    {
      let overloads_update = MessageDigest.update.overloads
      for (const overload of overloads_update) {
        overload.implementation = function () {
          const algorithm = this.getAlgorithm()
          showDivider(algorithm)
          showStacks(algorithm)
          Encode.toAll(`${algorithm} update data`, arguments[0])
          return this.update(...arguments)
        }
      }
  
      let overloads_digest = MessageDigest.digest.overloads
      for (const overload of overloads_digest) {
        overload.implementation = function () {
          const algorithm = this.getAlgorithm()
          showDivider(algorithm)
          showStacks(algorithm)
          const result = this.digest(...arguments)
          if (arguments.length === 1) {
            Encode.toAll(`${algorithm} update data`, arguments[0])
          } else if (arguments.length === 3) {
            Encode.toAll(`${algorithm} update data`, arguments[0])
          }
  
          Encode.toResult(`${algorithm} digest result`, result)
          return result
        }
      }
    }
  
    const Mac = Java.use('javax.crypto.Mac')
    {
      Mac.init.overload('java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (key, AlgorithmParameterSpec) {
        return this.init(key, AlgorithmParameterSpec)
      }
      Mac.init.overload('java.security.Key').implementation = function (key) {
        const algorithm = this.getAlgorithm()
        showDivider(algorithm)
        showStacks(algorithm)
        const keyBytes = key.getEncoded()
        Encode.toAll(`${algorithm} init Key`, keyBytes)
        return this.init(...arguments)
      }
  
  
      let overloads_doFinal = Mac.doFinal.overloads
      for (const overload of overloads_doFinal) {
        overload.implementation = function () {
          const algorithm = this.getAlgorithm()
          showDivider(algorithm)
          showStacks(algorithm)
          const result = this.doFinal(...arguments)
          if (arguments.length === 1) {
            Encode.toAll(`${algorithm} update data`, arguments[0])
          } else if (arguments.length === 3) {
            Encode.toAll(`${algorithm} update data`, arguments[0])
          }
  
          Encode.toResult(`${algorithm} doFinal result`, result)
          return result
        }
      }
    }
  
    const Cipher = Java.use('javax.crypto.Cipher')
    {
      let overloads_init = Cipher.init.overloads
      for (const overload of overloads_init) {
        overload.implementation = function () {
          const algorithm = this.getAlgorithm()
          showDivider(algorithm)
          showStacks(algorithm)
  
          if (arguments[0]) {
            const mode = arguments[0]
            console.log(`${algorithm} init mode`, mode)
          }
  
          if (arguments[1]) {
            const className = JSON.stringify(arguments[1])
            // 安卓10以上私钥是有可能输出不了的
            if (className.includes('OpenSSLRSAPrivateKey')) {
              // const keyBytes = arguments[1];
              // console.log(`${algorithm} init key`, keyBytes);
            } else {
              const keyBytes = arguments[1].getEncoded()
              Encode.toAll(`${algorithm} init key`, keyBytes)
            }
          }
  
          if (arguments[2]) {
            const className = JSON.stringify(arguments[2])
            if (className.includes('javax.crypto.spec.IvParameterSpec')) {
              const iv = Java.cast(arguments[2], Java.use('javax.crypto.spec.IvParameterSpec'))
              const ivBytes = iv.getIV()
              Encode.toAll(`${algorithm} init iv`, ivBytes)
            } else if (className.includes('java.security.SecureRandom')) {
            }
          }
  
          return this.init(...arguments)
        }
      }
  
      let overloads_doFinal = Cipher.doFinal.overloads
      for (const overload of overloads_doFinal) {
        overload.implementation = function () {
          const algorithm = this.getAlgorithm()
          showDivider(algorithm)
          showStacks(algorithm)
          const result = this.doFinal(...arguments)
          if (arguments.length === 1) {
            Encode.toAll(`${algorithm} update data`, arguments[0])
          } else if (arguments.length === 3) {
            Encode.toAll(`${algorithm} update data`, arguments[0])
          }
  
          Encode.toResult(`${algorithm} doFinal result`, result)
          return result
        }
      }
    }
  
    const Signature = Java.use('java.security.Signature')
    {
      let overloads_update = Signature.update.overloads
      for (const overload of overloads_update) {
        overload.implementation = function () {
          const algorithm = this.getAlgorithm()
          showDivider(algorithm)
          showStacks(algorithm)
          Encode.toAll(`${algorithm} update data`, arguments[0])
          return this.update(...arguments)
        }
      }
  
      let overloads_sign = Signature.sign.overloads
      for (const overload of overloads_sign) {
        overload.implementation = function () {
          const algorithm = this.getAlgorithm()
          showDivider(algorithm)
          showStacks(algorithm)
          const result = this.sign()
          Encode.toResult(`${algorithm} sign result`, result)
          return this.sign(...arguments)
        }
      }
    }
  })
```


---

## 10. Hooking Packed Apps (enumerateClassLoadersSync)

Hooking after packing requires the classLoader: every loaded dex corresponds to one classLoader, and for the functions between them to call each other, the other side's classLoader is also required; there is no way to use them directly. Our hooks need these as well, because only this way can we hook the concrete address of the Java function, turning it into a native function to hook:

```javascript
Java.enumerateClassLoadersSync().forEach(classLoader => {
    try {
        if (classLoader.loadClass("ot2.b")) {
            Java.classFactory.loader = classLoader;
            console.log(classLoader)
            let C82252b = Java.use("ot2.b");
            C82252b["getBdOz"].implementation = function (context) {
                console.log(`C82252b.getBdOz is called: context=${context}`);
                let result = this["getBdOz"](context);
                console.log(`C82252b.getBdOz result=${result}`);
                return result;
            };
        }
    } catch (e) {
        // console.log(e)
    }
})
```


## Related Docs

- Algorithm restoration and offline replay roadmap: [../../10-algo-restore/algo-restoration-methodology.md](../../10-algo-restore/algo-restoration-methodology.md)
