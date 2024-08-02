var CallBackSet = new Set();
var callbackMap = new Map();


function hookLoadClass() {

  var clazzClassLoader = Java.use("java.lang.ClassLoader")
  clazzClassLoader.loadClass.overload(
    "java.lang.String",
    "boolean"
  ).implementation = function(name, resolve) {
    try {
      var result = this.loadClass(name, resolve)
    //   console.log("Loaded class: " + name)
      if (callbackMap.has(name)) {
        // trigger callbacks for this class
        let classLoader = this
        let clazz = Java.ClassFactory.get(classLoader).use(name)
        let callbacks = callbackMap.get(name)
        if (callbacks !== undefined) {
          for (let callback of callbacks) {
            callback(clazz)
          }
        }
      }
      return result
    } catch (e) {
        // console.log("exception loading class: " + name)
      throw e
    } finally {
    }
  }
}

function JavaUseOnceLoaded(className, callback){
    try{
        callback(Java.use(className))
    }
    catch(e) {
        if (callbackMap.has(className)) {
            let callbackSet = callbackMap.get(className)
            if (callbackSet !== undefined) callbackSet.add(callback) // else should not happen (currently no entry gets deleted)
          } else {
            let newCallbackSet = new Set()
            newCallbackSet.add(callback)
            callbackMap.set(className, newCallbackSet)
          }
    }
}

Java.performNow(() => {
    var dynamicClassName = ""
  
    console.log("Trying Java.use() on " + dynamicClassName + "...")
    try {
      let clazz = Java.use(dynamicClassName)
    } catch (e) {
      console.log(Java.use("android.util.Log").getStackTraceString(e))
    }
  
    console.log(
      "Registering callbacks with JavaUseOnceLoaded for " +
        dynamicClassName +
        "..."
    )
  
    // first callback only for printing
    JavaUseOnceLoaded(dynamicClassName, clazz => {
        console.log(clazz.class.getName())
        clazz.class.getDeclaredMethods().forEach((x) => {
          traceJavaMethod(clazz, x.getName())
        })
    })
})

function traceJavaMethod(classReference, methodName) {
  var clazz = classReference;
  var className = clazz.class.getName();
  var func = methodName;


  var overloads = clazz[func].overloads;

  for (var i in overloads) {
      if (overloads[i].hasOwnProperty('argumentTypes') || overloads[i]['argumentTypes'] != undefined) {
          var parameters = [];
          var curArgumentTypes = overloads[i].argumentTypes, args = [], argLog = '[';
          for (var j in curArgumentTypes) {
              var cName = curArgumentTypes[j].className;
              parameters.push(cName);
              argLog += "'(" + cName + ") ' + v" + j + ",";
              args.push('v' + j);
          }
          argLog += "]";

          var identify = className + "." + methodName;
          
          var script = "var ret = this." + func + '(' + args.join(',') + ") || '';\n"
              // + "var jAndroidLog = Java.use('android.util.Log'), jException = Java.use('java.lang.Exception');\n"
              // + "var tmp = '" + identify + "';\n"
              // + "console.log(tmp + JSON.stringify(" + argLog + ") + JSON.stringify(ret) + jAndroidLog.getStackTraceString(jException.$new()));\n"
              // + "console.log(tmp)\n"

          if (overloads[i]['returnType']['className'] === 'void') {
              script += "return;";
          }
          else {
              script += "return ret;";
          }

          // console.log(script)

          args.push(script);

          clazz[func].overload.apply(clazz[func], parameters).implementation = Function.apply(null, args);
      }
  }
};


Java.perform(hookLoadClass)
