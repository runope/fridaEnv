/*
 * @Author: Runope
 * @Date: 2021-06-03 19:37:35
 * @LastEditors: Runope
 * @LastEditTime: 2021-06-03 20:25:42
 * @Description: file content
 * @contact: runope@qq.com
 */
import {log, print} from "../../logger";

export namespace unpack {

    export function legu() {

        const strstr_ptr = Module.findExportByName(null, 'strstr')

        if (null == strstr_ptr) {
            return;
        }

        const strstr_func = new NativeFunction(strstr_ptr, 'int', ['pointer', 'pointer'])

        print(strstr_ptr.toString())

        Interceptor.replace(strstr_ptr, new NativeCallback(function (str1, str2) {
            if(str2.readCString() == 'xposed') {
                // print('hook strstr -> xposed')
                return 1;
            }
            return strstr_func(str1, str2) 

        }, 'int', ['pointer', 'pointer']));

        const libart = Process.findModuleByName("libart.so");
        if (libart) {
            //console.log("found linker");
            var symbols = libart.enumerateSymbols();
            for (var i = 0; i < symbols.length; i++) {
                var name = symbols[i].name;
                if (name.indexOf("defineClassNative") >= 0){
                    const defineClassNative_addr = symbols[i].address;
                    Interceptor.attach(defineClassNative_addr, {
                        onEnter: function(args) {
                            
                            print('defineClassNative call!')
                            print(hexdump(args[3], {length: 100}))
                            
                        },
                        onLeave: function(ret) {

                        }
                    })
                   // console.log("call_function",JSON.stringify(symbols[i]));
                }

     
            }
        }
    }
}