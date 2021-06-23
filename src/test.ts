/*
 * @Author: Runope
 * @Date: 2021-05-31 17:00:04
 *
 * @LastEditors: Runope
 * @LastEditTime: 2021-06-18 10:30:44
 * @Description: file content
 * @contact: runope@qq.com
 */

import { unpack } from "../agent/utils/android/unpack";
import { print } from "../agent/logger";
import { hooklib } from "../agent/utils/android/hooklib";
import { anti } from "../agent/utils/android/anti";
import {hook_decode} from "../agent/utils/android/decodehook"


function exploit() {
    Java.perform(() => {

        // anti.anti_debug()
        // unpack.legu()
        // hook_decode()
        // hooklib.hook_libc_sendto()

        Java.perform(() => {
            let callmodule_base_pointer = Module.findBaseAddress("libcallmodule_balanar.so");

            let dst_pointer = callmodule_base_pointer?.add(0x4e3449)
            console.log(`dst_pointer: ${dst_pointer}`);
            

            if (!dst_pointer) throw 'dst_pointer is null'
            Interceptor.attach(dst_pointer, {
                onEnter: (args: any) => {
                    console.log(`catch dst args[0]: ${args[0]}`)
                },
                onLeave: (retval: any) => {

                }
            })

        })

    });
}



exploit();
