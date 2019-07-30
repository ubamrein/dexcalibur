const Adb = require('./AdbWrapper.js');
const Path = require('path');
const Process = require('child_process');
var Package = require('./AppPackage');
const fs = require('fs');
const https = require('https');
const lzma = require('lzma-native');

class PackagePatcher {
    constructor(pkgName,config=null, apkHelper) {
        this.apkHelper = apkHelper;
        this.currentPackageName = pkgName;
        this.config = config;
        this.packages = [];
        this.smaliCode = "const-string v$d$ \"frida-gadget\"\n invoke-static {v$d$} Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n";
        this.Bridges = {
            ADB: new Adb(this.config.getAdbPath(),null)
        };
    }
    /**
     * Pull a Package from the Device and Patch its MainActivity to load frida-gadget,
     * as well as copying the library into the apk
     * 
     * @param {*} package_name The package name
     * 
     */
    patchPackage(packageIdentifier) {
        var mainActivityReg = new RegExp(/\s*\<activity (\s*(?:[A-z:]*)=\"(?:[A-z@.|\/_-]*)\"\s*)*(android\:name=\"(?<main_activity>[A-z.]*)\")(\s*(?:[A-z:]*)=\"(?:[A-z@.|\/_-]*)\"\s*)*>[\s<A-z\-\>:=\".\/]*<action android:name=\"android.intent.action.MAIN\"\s*\/>/);
        var manifestPath = Path.join(this.config.workspacePath, packageIdentifier, 'dex','AndroidManifest.xml');
        var manifest = fs.readFileSync(manifestPath).toString('ascii');
        if(mainActivityReg.test(manifest)){
            //we found the main activity
            var match = mainActivityReg.exec(manifest);
            var mainActivity = match.groups['main_activity'];
           mainActivity = mainActivity.replace(/\./g, Path.sep);
            var mainActivityFile = Path.join(this.config.workspacePath, packageIdentifier, 'dex','smali', mainActivity+ '.smali');
            var i =0;
            while(!fs.existsSync(mainActivityFile)) {
                mainActivityFile = Path.join(this.config.workspacePath, packageIdentifier, 'dex','smali_classes'+i, mainActivity+ '.smali');
                i ++;
                if(i > 15) {
                    console.error("too many classes");
                    console.log(mainActivity);
                    break;
                }
            }
            //now we need to inject the smali code 
            this.injectSmaliCode(mainActivityFile);
            this.putFridaGadget(packageIdentifier);
            //patch the manifest
            manifest = this.setApkAsDebuggable(manifest);
            manifest = this.setBackup(manifest);
            manifest = this.setCertificateUserStore(manifest, packageIdentifier);
            fs.writeFileSync(manifestPath,manifest);
        } else {
            console.error("Could not find MainActivity");
            console.log(manifest);
        }
    }
/**
 * 
 * @param {*} fridaVersion  frida-gadget version
 * @param {*} arch  the target ABI
 * @param {*} platform for now only android
 */
    getFridaDownloadLink(abi, fridaVersion = "12.6.6", platform = "android" )
    {
        var arch = abi;
        if(abi == "armeabi-v7a") {
            arch = "arm";
        } else if (abi == "arm64-v8a"){
            arch = "arm64";
        }
        
        return `https://github.com/frida/frida/releases/download/${fridaVersion}/frida-gadget-${fridaVersion}-${platform}-${arch}.so.xz`;
    }
    /**
     * Download frida-gadget and put it into the ABI specific folders
     * @param {*} packageIdentifier The package we are intersted in
     */
    putFridaGadget(packageIdentifier) {
        /**
         * We probably should also put the ones for the emulator
         * lib/armeabi-v7a
         * lib/arm64-v8a
         * lib/x86
         * lib/x86_64
         */
        var abis = ["armeabi-v7a", "arm64-v8a","x86","x86_64"];
        var libDir = Path.join(this.config.workspacePath, packageIdentifier, "dex", "lib");
        if(!fs.existsSync(libDir)){
            fs.mkdirSync(libDir);
        }
        
        for(let abi in abis){
            if(!fs.existsSync(Path.join(libDir, abis[abi]))) {
                fs.mkdirSync(Path.join(libDir, abis[abi]));
            }
            const file = fs.createWriteStream(Path.join(libDir,abis[abi],"libfrida-gadget.so"));
            
            const request = https.get(this.getFridaDownloadLink(abis[abi]), function(response) {
                if(response.statusCode == 302 || response.statusCode == 301) {
                    console.log(response.headers.location);
                    https.get(response.headers.location, function(resp) {
                        var compressor = lzma.createDecompressor();
                        resp.pipe(compressor).pipe(file);
                        file.on('finish', function() {
                          file.close();  // close() is async, call cb after close completes.
                        });
                    })
                }
             
            });
        }
    }
    /**
     * 
     * @param {*} mainActivity file path of the main activity
     */
    injectSmaliCode(mainActivity) {
        var smaliContent = fs.readFileSync(mainActivity).toString("ascii");
        var constructor = this.findConstructor(smaliContent);
        smaliContent.replace(constructor.constructorCode, constructor.patchedConstructor);
        fs.writeFileSync(mainActivity,smaliContent);
    }
/**
 * 
 * @param {*} smaliContent content of the MainActivity smali code
 */
    findConstructor(smaliContent) {
        var constructorReg = new RegExp(/\.method public constructor <init>\(\)V[A-z.{}\/;->-_0-9()\s,"]*\.end method/);
        if(constructorReg.test(smaliContent)) {
            var constructorCode =  constructorReg.exec(smaliContent);
            return {
                constructorCode : constructorCode,
                patchedConstructor : this.patchConstructor(constructorCode[0])
            };
        }
        return undefined;
    }
/**
 * 
 * @param {*} constructorCode the constructor Code block
 */
    patchConstructor(constructorCode) {
        //update number of locals
        var getLocals = new RegExp(/\.locals (?<locals>[0-9]*)/);
        if(getLocals.test(constructorCode)) {
            var localsMatch = getLocals.exec(constructorCode);
            var locals = parseInt(localsMatch.groups["locals"]);
            var newLocals = locals + 1;
            if(newLocals > 16) {
                console.warn("we have more than 16 locals, could cause problems");
            }
            constructorCode.replace("locals "+locals, "locals "+newLocals);
            console.log(localsMatch.index);
            var firstPart = constructorCode.substr(0,localsMatch.index);
            var localPart = constructorCode.substr(localsMatch.index, localsMatch[0].length + localsMatch[1].length -1);
            var rest = constructorCode.substr(localsMatch.index + localsMatch[0].length + localsMatch[1].length);
            return firstPart 
                    + localPart.replace(locals, newLocals) 
                    + "\n"
                    + this.smaliCode.replace(/\$d\$/g,newLocals)
                    + rest;
        }
        return undefined;
    }
    /**
     * Set apk as debuggable to allow the run-as
     * @param {*} manifestContent  the content of the Manifest file
     * TODO: If frida-server is running set ro.debuggable to true
     */
    setApkAsDebuggable(manifestContent) {
        return manifestContent;
    }
    /**
     * enable backup; If the App is not careful with sensitive data we can pull a backup and restore it back with
     * modified values 
     * @param {*} manifestContent the content of the Manifest file
     * 
     */
    setBackup(manifestContent) {
        return manifestContent;
    }
    /**
     * put networking rules to set user store as an allowed certificate store
     * This enables us to do MiM attacks using Charles or a similar proxy
     * @param {*} manifestContent The content of the manifest file
     * @param {*} packageIdentifier The package we are interested in
     */
    setCertificateUserStore(manifestContent, packageIdentifier){
        return manifestContent;
    }

    pullPackage(packageIdentifier) {
        var dstPath = Path.join(this.config.workspacePath, packageIdentifier, 'dex');
        var tmpPath = Path.join(this.config.workspacePath,packageIdentifier, packageIdentifier +  '.apk');

        var projectDir = Path.join(this.config.workspacePath, packageIdentifier);
        
        fs.mkdirSync(projectDir);
        fs.mkdirSync(dstPath);

        var pathResult = this.Bridges.ADB.getPackagePath(packageIdentifier);
        this.Bridges.ADB.pull(pathResult, tmpPath);
        this.apkHelper.extract(tmpPath, dstPath, true);
    }

    clear() {
        this.packages = [];
    }

    scanWorkspace() {
        var workspacePath = this.config.workspacePath;
        var dirs = fs.readdirSync(workspacePath);
        for(var dir in dirs) {
            var packageDir = Path.join(workspacePath, dirs[dir]);
            if(!fs.lstatSync(packageDir).isDirectory()) {
                continue;
            }
            if(fs.readdirSync(packageDir).includes("dex")) {
                //this probably is an package dir
                //check if it is already contained
                if(dirs[dir] in this.packages) {
                    continue;
                }

                var pkg = new Package({
                    packageIdentifier: dirs[dir],
                    packagePath:packageDir,
                    workspaceExists : true,
                    currentWd : dirs[dir] == this.currentPackageName
                });
                this.packages[pkg.packageIdentifier] = pkg;
            }
        }
    }

    scan(){
       this.count = 0;
       if(this.Bridges.ADB.isReady()){
           var pkgs = this.Bridges.ADB.listPackages();
           this.count += pkgs.length;

           for(let i in pkgs){
               this.packages[pkgs[i].packageIdentifier] = pkgs[i];
               this.packages[pkgs[i].packageIdentifier].workspaceExists = fs.existsSync(Path.join(this.config.workspacePath,pkgs[i].packageIdentifier));
               this.packages[pkgs[i].packageIdentifier].currentWd = pkgs[i].packageIdentifier === this.currentPackageName;
           }
           //ut.msgBox("Android packages", Object.keys(this.packages));
           console.log("Android packages", Object.keys(this.packages));
       }
        
   }

   toJsonObject(){
    let json = [];
    for(let i in this.packages){
        json.push(this.packages[i].toJsonObject())
    }
    return json;
};

    
}

module.exports = PackagePatcher;
