/*
 * @Author: Runope
 * @Date: 2021-05-31 15:59:24
 * @LastEditors: Runope
 * @LastEditTime: 2021-06-02 15:06:48
 * @Description: anti anti
 * @contact: runope@qq.com
 */

import {log} from "../../logger";
import {fridaCommon} from "../common";

const sslPinningPass = require("./repinning");
const unpinning = require("./multi_unpinning");

export namespace anti {

    /**
     * 动态加载 dex
     * 在利用 InMemoryDexClassLoader 加载内存 Dex 找不到类的情况下适用。
     * 调用方式：
     * FCAnd.anti.anti_InMemoryDexClassLoader(function(){
     *     const cls = Java.use('find/same/multi/dex/class');
     *     // ...
     * });
     *
     * 实现原理：
     * const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
     InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader')
     .implementation = function (buff, loader) {
            this.$init(buff, loader);
            var oldcl = Java.classFactory.loader;
            Java.classFactory.loader = this;
            callbackfunc();
            Java.classFactory.loader = oldcl;

            return undefined;
        }
     * @param callbackfunc
     *
     * @deprecated The method should not be used
     */
    export function anti_InMemoryDexClassLoader(callbackfunc: any) {
        throw new Error("deprecated method, should use:  FCAnd.useWithInMemoryDexClassLoader");
    }

    export function anti_debug() {
        anti_fgets();
        anti_exit();
        anti_fork();
        anti_kill();
        anti_ptrace();
    }

    export function anti_exit() {
        const exit_ptr = Module.findExportByName(null, 'exit');
        if (null == exit_ptr) {
            return;
        }
        Interceptor.replace(exit_ptr, new NativeCallback(function (code) {
            if (null == this) {
                return 0;
            }
            var lr = fridaCommon.getLR(this.context);
            log.i('exit debug', 'entry, lr: ' + lr);
            return 0;
        }, 'int', ['int', 'int']));
    }

    export function anti_kill() {
        const kill_ptr = Module.findExportByName(null, 'kill');
        if (null == kill_ptr) {
            return;
        }
        Interceptor.replace(kill_ptr, new NativeCallback(function (ptid, code) {
            if (null == this) {
                return 0;
            }
            var lr = fridaCommon.getLR(this.context);
            log.i('kill debug', 'entry, lr: ' + lr);
            return 0;
        }, 'int', ['int', 'int']));
    }

    /**
     * @state_name: cat /proc/xxx/stat ==> ...(<state_name>) S...
     *
     * anti fgets function include :
     * status->TracerPid, SigBlk, S (sleeping)
     * State->(package) S
     * wchan->SyS_epoll_wait
     */
    export function anti_fgets() {
        const tag = 'anti_fgets';
        const fgetsPtr = Module.findExportByName(null, 'fgets');
        log.i(tag, 'fgets addr: ' + fgetsPtr);
        if (null == fgetsPtr) {
            return;
        }
        var fgets = new NativeFunction(fgetsPtr, 'pointer', ['pointer', 'int', 'pointer']);
        Interceptor.replace(fgetsPtr, new NativeCallback(function (buffer, size, fp) {
            if (null == this) {
                return 0;
            }
            var logTag = null;
            // 进入时先记录现场
            const lr = fridaCommon.getLR(this.context);
            // 读取原 buffer
            var retval = fgets(buffer, size, fp);
            var bufstr = (buffer as NativePointer).readCString();

            if (null != bufstr) {
                if (bufstr.indexOf("TracerPid:") > -1) {
                    buffer.writeUtf8String("TracerPid:\t0");
                    logTag = 'TracerPid';
                }
                //State:	S (sleeping)
                else if (bufstr.indexOf("State:\tt (tracing stop)") > -1) {
                    buffer.writeUtf8String("State:\tS (sleeping)");
                    logTag = 'State';
                }
                // ptrace_stop
                else if (bufstr.indexOf("ptrace_stop") > -1) {
                    buffer.writeUtf8String("sys_epoll_wait");
                    logTag = 'ptrace_stop';
                }

                //(sankuai.meituan) t
                else if (bufstr.indexOf(") t") > -1) {
                    buffer.writeUtf8String(bufstr.replace(") t", ") S"));
                    logTag = 'stat_t';
                }

                // SigBlk
                else if (bufstr.indexOf('SigBlk:') > -1) {
                    buffer.writeUtf8String('SigBlk:\t0000000000001204');
                    logTag = 'SigBlk';
                }
                if (logTag) {
                    log.i(tag + " " + logTag, bufstr + " -> " + buffer.readCString() + ' lr: ' + lr
                        + "(" + fridaCommon.getModuleByAddr(lr) + ")");
                }
            }
            return retval;
        }, 'pointer', ['pointer', 'int', 'pointer']));
    }

    export function anti_ptrace() {
        var ptrace = Module.findExportByName(null, "ptrace");
        if (null != ptrace) {
            ptrace = ptrace.or(1);
            log.i('anti_ptrace', "ptrace addr: " + ptrace);
            // Interceptor.attach(ptrace, {
            //     onEnter: function (args) {
            //         log.i('anti_ptrace', 'entry');
            //     }
            // });
            Interceptor.replace(ptrace.or(1), new NativeCallback(function (p1: any, p2: any, p3: any, p4: any) {
                log.i('anti_ptrace', 'entry');
                return 1;
            }, 'long', ['int', "int", 'pointer', 'pointer']));
        }
    }

    /**
     * 适用于每日优鲜的反调试
     */
    export function anti_fork() {
        var fork_addr = Module.findExportByName(null, "fork");
        log.i('anti_ptrace', "fork_addr : " + fork_addr);
        if (null != fork_addr) {
            // Interceptor.attach(fork_addr, {
            //     onEnter: function (args) {
            //         log.i('fork_addr', 'entry');
            //     }
            // });
            Interceptor.replace(fork_addr, new NativeCallback(function () {
                log.i('fork_addr', 'entry');
                return -1;
            }, 'int', []));
        }
    }

    export function anti_sslLoadCert(cerPath: string) {
        sslPinningPass.ssl_load_cert(cerPath);
    }

    export function anti_ssl_unpinning() {
        setTimeout(unpinning.multi_unpinning, 0);
    }
}
