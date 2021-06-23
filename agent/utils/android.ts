/*
 * @Author: Runope
 * @Date: 2021-05-31 15:26:36
 * @LastEditors: Runope
 * @LastEditTime: 2021-05-31 16:24:45
 * @Description: frida script of android utils 
 * @contact: runope@qq.com
 */


import {log} from "../logger"

export namespace androidUtils {



    export function parseObject(data: any) {
        try {
            const declaredFields = data.class.getDeclaredFields();
            let res = {};
            for (let i = 0; i < declaredFields.length; i++) {
                const field = declaredFields[i];
                field.setAccessible(true);
                const type = field.getType();
                let fdata = field.get(data);
                if (null != fdata) {
                    if (type.getName() != "[B") {
                        fdata = fdata.toString();
                    }
                    else {
                        fdata = Java.array('byte', fdata);
                        fdata = JSON.stringify(fdata);
                    }
                }
                // @ts-ignore
                res[field.getName()] = fdata;
            }
            return JSON.stringify(res);
        } catch (e) {
            return "parseObject except: " + e.toString();
        }

    }

    export function registGson():void {
        try {
            let dexpath = '/data/local/tmp/r0gson.dex';
            Java.openClassFile(dexpath).load();
        } catch (e) {
            log.e('registGson', 'exception, please try to run `initAndroidEnv.py`')
        }
    }

    /**
     * @description: Convert Java objects to JSON
     * @param {any} obj: android object
     * @return {*} 
     */
    export function toJSONString(obj: any):string {
        if(obj == null) {
            return "obj is null!"
        }

        let retStr = ""
        let GsonBuilder = null
        try {
            GsonBuilder = Java.use('com.r0ysue.gson.GsonBuilder');
        } catch (e) {
            androidUtils.registGson();
            GsonBuilder = Java.use('com.r0ysue.gson.GsonBuilder');
        }
        if (null != GsonBuilder) {
            try {
                const gson = GsonBuilder.$new().serializeNulls()
                    .serializeSpecialFloatingPointValues()
                    .disableHtmlEscaping()
                    .setLenient()
                    .create();
                    retStr = gson.toJson(obj);
            } catch (e) {
                log.e('gson.toJson', 'exceipt: ' + e.toString());
                retStr = androidUtils.parseObject(obj);
            }
        }

        return retStr;

    }

    /**
     * 
     * @param {string} str_tag: provide a tag when printing   
     * @returns 
     */
    export function showStacks(str_tag:string) {
        var Exception=  Java.use("java.lang.Exception");
        var ins = Exception.$new("Exception");
        var straces = ins.getStackTrace();
     
        if (undefined == straces || null  == straces) 
        {
            return;
        }
     
        console.log("=============================" + str_tag + " Stack strat=======================");
        console.log("");
     
        for (var i = 0; i < straces.length; i++)
        {
            var str = "   " + straces[i].toString();
            console.log(str);
        }
     
        console.log("");
        console.log("=============================" + str_tag + " Stack end=======================\r\n");
        Exception.$dispose();
     };
}