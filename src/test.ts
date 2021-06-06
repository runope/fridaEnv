/*
 * @Author: Runope
 * @Date: 2021-05-31 17:00:04
 *
 * @LastEditors: Runope
 * @LastEditTime: 2021-06-04 17:21:59
 * @Description: file content
 * @contact: runope@qq.com
 */

import { unpack } from "../agent/utils/android/unpack";
import { print } from "../agent/logger";
import { hooklib } from "../agent/utils/android/hooklib";
import { anti } from "../agent/utils/android/anti";

function exploit() {
    Java.perform(() => {

        anti.anti_debug()
    });
}



exploit();
