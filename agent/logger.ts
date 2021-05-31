/*
 * @Author: Runope
 * @Date: 2021-05-31 14:38:36
 * @LastEditors: Runope
 * @LastEditTime: 2021-05-31 16:17:20
 * @Description: print log
 * @contact: runope@qq.com
 */


export function print(message: string): void {
    console.log(message);
}

export class log {
    private static bDebug: boolean = true;

    static d(tag: string, str: string) {
        if (this.bDebug) {
            log.log_(console.log, 'DEBUG', tag, str);
        }
    }

    static i(tag: string, str: string) {
        log.log_(console.log, 'INFO', tag, str);
    }

    static w(tag: string, str: string) {
        log.log_(console.warn, 'WARN', tag, str);
    }

    static e(tag: string, str: string) {
        log.log_(console.error, 'ERROR', tag, str);
    }

    static log_(logfunc: (message?: any, ...optionalParams: any[]) => void , leval: string, tag: string, str: string) {
        logfunc(`[${leval}][${new Date().toLocaleString('zh-CN')}][${Process.getCurrentThreadId()}][${tag}]: ${str}`);
    }

    static send(tag: string, content: string) {
        let tid = Process.getCurrentThreadId();
        send(JSON.stringify({
            tid: tid,
            status: 'msg',
            tag: tag,
            content: content
        }));
    }
}