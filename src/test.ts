/*
 * @Author: Runope
 * @Date: 2021-05-31 17:00:04
 *
 * @LastEditors: Runope
 * @LastEditTime: 2021-06-15 14:11:27
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

        anti.anti_debug()
        hook_decode()


        // const shield_base:any = Module.findBaseAddress("libshield.so")

        // const sub_ABB8 = ptr(shield_base).add(0xabb8).add(0x1)

        // Interceptor.attach(sub_ABB8, {
        //     onEnter: (args) => {
        //         print(hexdump(args[0], {length: 256}))
        //     },
        //     onLeave: (retval) => {

        //     }
        // })

    });
}



exploit();
