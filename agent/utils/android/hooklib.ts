import { assert } from "console";
import { log, print } from "../../logger";




export namespace hooklib {

    export function hook_initArray() {

        let linker = null

        if (Process.pointerSize == 4) {
            linker = Process.findModuleByName("linker");
        } else if (Process.pointerSize == 8) {
            linker = Process.findModuleByName("linker64");
        }

        var addr_call_function = null;
        var addr_call_constructors = null;

        if (linker) {
            var symbols = linker.enumerateSymbols();
            for (var i = 0; i < symbols.length; i++) {
                var name = symbols[i].name;
                if (name.indexOf("call_function") >= 0) {
                    addr_call_function = symbols[i].address;
                }
                if (name.indexOf("call_constructors") >= 0) {
                    addr_call_constructors = symbols[i].address;
                    print(`found call_constructors: ${addr_call_constructors}`)
                }
            }

        }

        let g_libnative: any = null
        let g_start_byte: any = null
        let g_byte_len: any = null

        if (addr_call_constructors) {
            Interceptor.attach(addr_call_constructors, {
                onEnter: (args) => {
                    // here 
                    let soname = args[0].readCString()
                    if (soname == null) {
                        throw ("soname is null!")
                        return
                    }
                    if (soname.indexOf("libnative-lib.so") >= -1) {
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

        if (addr_call_function) {
            Interceptor.attach(addr_call_function, {
                onEnter: (args) => {
                    let typename = args[0].readCString()
                    let soname = args[2].readCString()
                    if (soname == null) {
                        throw ("soname is null!")
                        return
                    }
                    if (typename == "function" && soname.indexOf("libnative-lib.so") >= -1) {
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
                    var bs = g_start_byte.readByteArray(g_byte_len);
                    var start = -1;
                    var preu8 = 0;
                    for (var i = 0; i < g_byte_len; i++) {
                        var valu8 = g_start_byte.add(i).readU8();
                        if (valu8 == 0) {
                            if (preu8 != 0) {
                                console.log("so addr[0x" + (g_start_byte.add(start + 1) - g_libnative.base).toString(16) + "]->", g_start_byte.add(start + 1).readCString());
                            }
                            start = i;
                        }
                        preu8 = valu8;
                    }
                }
            })
        }

    }



    export function hook_libc_sendmsg() {

        Java.perform(function () {

            var libc_base_pointer = Module.findBaseAddress("libc.so");
            var sendMsg_pointer = Module.findExportByName("libc.so", "sendmsg");

            console.log("--> libc.so base pointer: " + libc_base_pointer);
            console.log("--> sendMsg pointer: " + sendMsg_pointer);

            // sendmsg(fd, &mhdr, 0)
            // /* msg_name：数据的目的地址，网络包指向sockaddr_in, netlink则指向sockaddr_nl;
            //     msg_namelen: msg_name 所代表的地址长度
            //     msg_iov: 指向的是缓冲区数组
            //     msg_iovlen: 缓冲区数组长度
            //     msg_control: 辅助数据，控制信息(发送任何的控制信息)
            //     msg_controllen: 辅助信息长度
            //     msg_flags: 消息标识
            // */
            // struct msghdr {
            //     void         *msg_name;       /* optional address */
            //     socklen_t     msg_namelen;    /* size of address */
            //     struct iovec *msg_iov;        /* scatter/gather array */
            //     size_t        msg_iovlen;     /* # elements in msg_iov */
            //     void         *msg_control;    /* ancillary data, see below */
            //     size_t        msg_controllen; /* ancillary databuffer len */
            //     int           msg_flags;      /* flags on received message */
            // };
            // /* iov_base: iov_base指向数据包缓冲区，即参数buff，iov_len是buff的长度。msghdr中允许一次传递多个buff，
            //     以数组的形式组织在 msg_iov中，msg_iovlen就记录数组的长度（即有多少个buff）
            // */
            // struct iovec {                    /* Scatter/gather arrayitems */
            //     void *iov_base;               /*Starting address */
            //     size_t iov_len;               /* Number of bytes to transfer*/
            // };

            if(!sendMsg_pointer) return;

            Interceptor.attach(sendMsg_pointer, {

                onEnter: function (args) {

                    console.log("hdr.Memory.readByteArray: ");
                    console.log(hexdump(args[1], {
                        offset: 0,
                        length: 256,
                        header: true,
                        ansi: false
                    }));
                    // args1: &mhdr, msg_iov_pointer": struct iovec *msg_iov;
                    var msg_iov_pointer = args[1].add(0x8).readPointer();
                    // void *iov_base;
                    var iov_base_pointer = msg_iov_pointer.readPointer();
                    // 没有计算长度，直接用的256
                    console.log("msg_iov_pointer().Memory.readByteArray: ");
                    console.log(hexdump(iov_base_pointer, {
                        offset: 0,
                        length: 256,
                        header: true,
                        ansi: false
                    }));

                    // print called stack
                    console.log('sendMsg called from:\n' +
                        Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\n') + '\n');
                },
                onLeave: function (retval) {

                    console.log("retval: " + retval);
                }
            });
        })
    }

    export function hook_libc_sendto() {

        Java.perform(function () {

            var libc_base_pointer = Module.findBaseAddress("libc.so");
            var sendto_pointer = Module.findExportByName("libc.so", "sendto");

            console.log("--> libc.so base pointer: " + libc_base_pointer);
            console.log("--> sendto pointer: " + sendto_pointer);

            if(!sendto_pointer) return;

            Interceptor.attach(sendto_pointer, {

                onEnter: function (args:any) {

                    var buffer_len = parseInt(args[2], 16);

                    // Reads the value of the specified address
                    var buffer = args[1].readByteArray(buffer_len);
                    // Prints hexadecimal and corresponding ASCII
                    console.log("sendto().Memory.readByteArray:");
                    console.log(hexdump(buffer, {
                        offset: 0,
                        length: buffer_len,
                        header: true,
                        ansi: false
                    }));

                    // print called stack
                    console.log('sendto called from:\n' +
                        Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\n') + '\n');
                },
                onLeave: function (retval) {

                    console.log("retval: " + retval);
                }
            });
        })
    }
}