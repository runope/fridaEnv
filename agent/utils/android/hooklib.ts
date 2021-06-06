import { assert } from "console";
import { print } from "../../logger";




export namespace hooklib {

    export function hook_initArray() {

        let linker = null

        if(Process.pointerSize == 4) {
            linker = Process.findModuleByName("linker");
        }else if (Process.pointerSize == 8) {
            linker = Process.findModuleByName("linker64");
        }

        var addr_call_function =null;
        var addr_call_constructors = null;

        if (linker) {
            var symbols = linker.enumerateSymbols();
            for (var i = 0; i < symbols.length; i++) {
                var name = symbols[i].name;
                if (name.indexOf("call_function") >= 0){
                    addr_call_function = symbols[i].address;
                }               
                if (name.indexOf("call_constructors") >= 0){
                    addr_call_constructors = symbols[i].address;
                    print(`found call_constructors: ${addr_call_constructors}`)
                }
            }

        }

        let g_libnative:any = null
        let g_start_byte:any = null
        let g_byte_len:any = null

        if(addr_call_constructors) {
            Interceptor.attach(addr_call_constructors, {
                onEnter: (args) => {
                    // here 
                    let soname = args[0].readCString()
                    if (soname == null) {
                        throw ("soname is null!")
                        return
                    }
                    if(soname.indexOf("libnative-lib.so") >= -1) {
                        let libnative = Process.findModuleByName("libnative-lib.so")
                        g_libnative = libnative
                        g_start_byte = g_libnative?.base.add(0x1B008)
                        g_byte_len = 0x1B0C0 - 0x1B008
                        print(`call_constructors onEnter: ${soname}, ${g_libnative?.base}`)
                    }
                },
                onLeave: (retval) => {

                }
            })
        }

        if(addr_call_function) {
            Interceptor.attach(addr_call_function, {
                onEnter: (args) => {
                    let typename = args[0].readCString()
                    let soname = args[2].readCString()
                    if (soname == null) {
                        throw ("soname is null!")
                        return
                    }
                    if(typename == "function" && soname.indexOf("libnative-lib.so") >= -1) {
                        let funcaddr = args[1]
                        print(`call_function onEnter addr: ${funcaddr}`)
                        Interceptor.attach(funcaddr, {
                            onEnter: (args) => {
                                print(`-> call ${funcaddr} onEnter`)
                            },
                            onLeave: (retval) => {
                                print(`-> call ${funcaddr} onLeave`)
                            }
                        })
                        print(`before function -> ${g_start_byte.readByteArray(g_byte_len)}`)
                    }
                },
                onLeave: (retval) => {
                    console.log(`after function -> ${g_start_byte.readByteArray(g_byte_len)}`);
                    var bs =  g_start_byte.readByteArray(g_byte_len);
                    var start = -1;
                    var preu8 = 0;
                    for(var i=0; i<g_byte_len; i++){
                        var valu8 =  g_start_byte.add(i).readU8();
                        if(valu8 == 0){
                            if(preu8 != 0){
                                console.log("so addr[0x"+(g_start_byte.add(start+1) - g_libnative.base).toString(16)+"]->",g_start_byte.add(start+1).readCString());
                            }
                            start = i;
                        }
                        preu8 = valu8;
                    }
                }
            })
        }

    }
}