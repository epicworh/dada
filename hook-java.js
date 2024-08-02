


function traceJavaMethod(className, methodName) {
    if (typeof className === 'undefined' | typeof methodName === 'undefined') {
        return;
    }
    var clazz = Java.use(className);
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
                + "var jAndroidLog = Java.use('android.util.Log'), jException = Java.use('java.lang.Exception');\n"
                + "var tmp = '" + identify + "';\n"
                + "console.log(tmp + JSON.stringify(" + argLog + ") + JSON.stringify(ret) + jAndroidLog.getStackTraceString(jException.$new()));\n"

            if (overloads[i]['returnType']['className'] === 'void') {
                script += "return;";
            }
            else {
                script += "return ret;";
            }

            args.push(script);

            clazz[func].overload.apply(clazz[func], parameters).implementation = Function.apply(null, args);
        }
    }
};
