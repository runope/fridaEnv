/*
 * @Author: Runope
 * @Date: 2021-06-03 19:37:35
 * @LastEditors: Runope
 * @LastEditTime: 2021-06-04 17:17:24
 * @Description: file content
 * @contact: runope@qq.com
 */
import {log, print} from "../../logger";
const dumpdex_yang = require("./dumpdex");

export namespace unpack {

    export function dumpdex() {
        dumpdex_yang.dump_dex()
    }

    export function legu() {

        let DEX_dic = new Map<string, number>()

        const strstr_ptr = Module.findExportByName(null, 'strstr')

        if (null == strstr_ptr) {
            return;
        }

        const strstr_func = new NativeFunction(strstr_ptr, 'int', ['pointer', 'pointer'])

        print(strstr_ptr.toString())

        Interceptor.replace(strstr_ptr, new NativeCallback(function (str1, str2) {
            if(str2.readCString() == 'xposed') {
                print('hook strstr -> xposed')
                return 1;
            }
            return strstr_func(str1, str2) 

        }, 'int', ['pointer', 'pointer']));

        let dex_count = 1

        const libart = Process.findModuleByName("libart.so");

        if (null == libart) {
            return;
        }

        var defineClassNative_addr = null;
        var symbols = libart.enumerateSymbols();
        for (var index = 0; index < symbols.length; index++) {
            var symbol = symbols[index];
            var symbol_name = symbol.name;
            //这个DefineClass的函数签名是Android9的
            //_ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcmNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE
            // if (symbol_name.indexOf("DexFile_defineClassNative") >= 0) {
            //     console.log(symbol_name, symbol.address);
            //     defineClassNative_addr = symbol.address;
            // }

            if (symbol_name.indexOf("ClassLinker") >= 0 &&
            symbol_name.indexOf("DefineClass") >= 0 &&
            symbol_name.indexOf("Thread") >= 0 &&
            symbol_name.indexOf("DexFile") >= 0) {
                console.log(symbol_name, symbol.address);
                defineClassNative_addr = symbol.address;
            }
        }

        if (defineClassNative_addr){
            Interceptor.attach(defineClassNative_addr, {
                onEnter: function(args:any) {
                    
                    let dex_file = args[5]

                    // print(hexdump(ptr(tmp), {length: 256}))           
                    var base:any = ptr(dex_file).add(Process.pointerSize).readPointer();
                    var size = ptr(dex_file).add(Process.pointerSize + Process.pointerSize).readUInt();
                    
                    DEX_dic.set(base, size)

                },
                onLeave: function(ret) {
    
                }
            })
        }
        setTimeout(legu_dexdump, 10000, DEX_dic)
                                       
    }

    function legu_dexdump(DEX_dic: Map<string, number>) {

        var dex_map: { [key: string]: number; } = {};
        DEX_dic.forEach((value, key) => { dex_map[key]=value})
        
        let dex_count = 1
    
        for(let k in dex_map){
            print(`base -> ${k};     value -> ${dex_map[k]}`);
            unpack.store_dex(k, dex_map[k], dex_count)
            dex_count++;
        }
    
    }

    function get_self_process_name() {
        var openPtr = Module.getExportByName('libc.so', 'open');
        var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
    
        var readPtr = Module.getExportByName("libc.so", "read");
        var read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);
    
        var closePtr = Module.getExportByName('libc.so', 'close');
        var close = new NativeFunction(closePtr, 'int', ['int']);
    
        var path = Memory.allocUtf8String("/proc/self/cmdline");
        var fd = open(path, 0);
        if (fd != -1) {
            var buffer:any = Memory.alloc(0x1000);
    
            var result:any = read(fd, buffer, 0x1000);
            close(fd);
            result = ptr(buffer).readCString();
            return result;
        }
    
        return "-1";
    }
    
    
    function mkdir(path:any) {
        var mkdirPtr = Module.getExportByName('libc.so', 'mkdir');
        var mkdir = new NativeFunction(mkdirPtr, 'int', ['pointer', 'int']);
    
    
    
        var opendirPtr = Module.getExportByName('libc.so', 'opendir');
        var opendir = new NativeFunction(opendirPtr, 'pointer', ['pointer']);
    
        var closedirPtr = Module.getExportByName('libc.so', 'closedir');
        var closedir = new NativeFunction(closedirPtr, 'int', ['pointer']);
    
        var cPath = Memory.allocUtf8String(path);
        var dir = opendir(cPath);
        if (dir != 0) {
            closedir(dir);
            return 0;
        }
        mkdir(cPath, 755);
        chmod(path);
    }
    
    function chmod(path:any) {
        var chmodPtr = Module.getExportByName('libc.so', 'chmod');
        var chmod = new NativeFunction(chmodPtr, 'int', ['pointer', 'int']);
        var cPath = Memory.allocUtf8String(path);
        chmod(cPath, 755);
    }

    function parse_DexFile(dex_file: any, dex_count: number): number {
        //ptr(dex_file).add(Process.pointerSize) is "const uint8_t* const begin_;"
        //ptr(dex_file).add(Process.pointerSize + Process.pointerSize) is "const size_t size_;"
        var base:any = ptr(dex_file).add(Process.pointerSize).readPointer();
        var size = ptr(dex_file).add(Process.pointerSize + Process.pointerSize).readUInt();


        print(`base -> ${base};        size -> ${size}`)


        var magic:any = ptr(base).readCString();

        if (magic.indexOf("dex") == 0) {

            // store_dex(base, size, dex_count)
        }
        
        return dex_count;
    }

    export function store_dex(base: any, size: any, dex_count: any){
        var process_name = get_self_process_name();
            if (process_name != "-1") {
                var dex_dir_path = "/data/data/" + process_name + "/files/dump_dex_" + process_name;
                mkdir(dex_dir_path);
                var dex_path = dex_dir_path + "/class" + (dex_count == 1 ? "" : dex_count) + ".dex";
                console.log("[find dex]:", dex_path);
                var fd = new File(dex_path, "wb");
                if (fd && fd != null) {
                    dex_count++;
                    var dex_buffer:any = ptr(base).readByteArray(size);
                    fd.write(dex_buffer);
                    fd.flush();
                    fd.close();
                    console.log("[dump dex]:", dex_path);

                }
            }
    }
}