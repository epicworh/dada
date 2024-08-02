# dada

dada is a list of fri(da) script templates that would be helpful in debugging your application. You install frida via pip and run frida-server on your target. Then you proceed to run the command below:
```
frida -U -l hook-dynamic-java.js -f "YOUR APPLICATION"
```

### TODO
Add support for dynamically loaded native function.

## Hook native
hook-native.js allows you to hook native function loaded by shared library

The function declaration is as follows:
```
traceNativeMethod(moduleName, nameOrOffset, backtrace = false, regReturn = NULL, ...argsOps)
traceNativeMethod('libc.so', "open", false, 'int', "string", 'int', 'buffer')
traceNativeMethod('libc.so', 0xfff, false, 'int', "string", 'int', 'buffer')
```
1. moduleName is the name of the shared library e.g. lib.so
2. nameOrOffset is the name of the (a) function or the (b) offset in hexdecimal from the base address of the shared library
3. backtrace is to determine if you would want to print the backtrace
4. regReturn is the format to print your returned object
5. argsOps is the format to print your args in register x0 .. to .. xN


Format supported includes int, string and buffer

### TODO
Add dynamic pointer instrumentation. 
i.e. add 0x50 to r1 and print the buffer 

## Hook java
Hook java is just a template to hook java function. This is easily found online in frida codeshare.

## Hook dynamic java
Not all Java classes/methods are loaded upon the application startup. Some are registered dynamically. This script enables you to listen to the ClassLoader and hook onto the function when your target is loaded in.

You would need to change the variable below to your target class
```
var dynamicClassName = 'your target class'
```
## Hook binder
This script enables you to hook onto the binder calls. This is only in the context of the application itself only to observe what this application sends out and recieves through binder.
