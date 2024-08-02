// script to trace all binder call and recieves in the process

var toHexString = function(byteArray) {
    return Array.from(byteArray, function(byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
};


Java.perform(() => {
    const Log = Java.use('android.util.Log')
    const BinderProxy = Java.use('android.os.BinderProxy')
    const Binder = Java.use('android.os.Binder')
    const Thread = Java.use('java.lang.Thread')
    const TAG = 'natsuki'
    function log(message) {
      Log.i(TAG, message)
    }
    function trace(...message) {
      console.log(...message)
    }
  
    function catching(block) {
      try {
        block()
      } catch (e) {
        console.error(e)
      }
    }
  
    // outgoing
    BinderProxy.transact.implementation = function (...args) {
      const callingStack = Thread.currentThread().getStackTrace()[3]
      catching(() => {
        const [code] = args
        const method = callingStack.getMethodName()
        const message = `----> (${code}:${
          this.getInterfaceDescriptor() || `?${callingStack.getClassName()}`
        }:${method})`
        log(message)
        trace(message)
      })
      return this.transact(...args)
    }
  
    // incoming
    Binder.execTransactInternal.implementation = function (...args) {
      catching(() => {
        const [code, , , , callingUid] = args
        const transactionName = this.getTransactionName(code) || `c${code}`
        const descriptor = this.getInterfaceDescriptor() || '?'
        const message = `<---- (${code}:${descriptor}:${transactionName}:u${callingUid})`
        log(message)
        trace(message)
      })
      return this.execTransactInternal(...args)
    }
  })
