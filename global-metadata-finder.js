function hook(addr) {
    Java.perform(function() {
        var Activity = Java.use('com.unity3d.player.UnityPlayerActivity');
        Activity.onCreate.implementation = function(bundle) {
            var onCreate = this.onCreate(bundle);
            console.log("start hooking addr: " + addr);
            var il2cpp = Module.findBaseAddress('libil2cpp.so');
            console.error('[!] il2cpp : ' + il2cpp);
            var LoadMetaDataFile = il2cpp.add(addr);
            Interceptor.attach(LoadMetaDataFile, {
                onLeave: function(retval) {
                    console.error('[!] LoadMetaDataFile retval : ' + retval);
                    send({status: "end"});
                }
            });
        }
    })
}