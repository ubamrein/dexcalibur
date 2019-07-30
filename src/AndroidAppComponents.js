

class IntentActionCriteria
{
    constructor(){
        this.name = null;
    }

    static fromXml(xmlobj){
        let o = new IntentActionCriteria();
        o.name = xmlobj['android:name'];
        return o;
    }

    toJsonObject(){
        let o = new Object();
        o.name = this.name;
        return o;
    }
}


class IntentCategoryCriteria
{
    constructor(){
        this.name = null;
    }

    static fromXml(xmlobj){
        let o = new IntentCategoryCriteria();
        o.name = xmlobj['android:name'];
        return o;
    }

    toJsonObject(){
        let o = new Object();
        o.name = this.name;
        return o;
    }
}

class IntentDataCriteria
{
    constructor(){
        this.scheme=null;
        this.host=null;
        this.port=null;
        this.path=null;
        this.pathPattern=null;
        this.pathPrefix=null;
        this.mimeType=null;
    }


    static fromXml(xmlobj){
        let o = new IntentDataCriteria();

        for(let i in xmlobj){
            if(i.startsWith('android:')){
                this[i.substr(8)] = xmlobj[i]; 
            }else{
                this[i] = xmlobj[i];
            }
        }

        return o;
    }


    toJsonObject(){
        let o = new Object();
        o.scheme = this.scheme;
        o.host = this.host;
        o.port = this.port;
        o.path = this.path;
        o.pathPattern = this.pathPattern;
        o.pathPrefix = this.pathPrefix;
        o.mimeType = this.mimeType;
        return o;
    }
}

class IntentFilter
{
    constructor(config){
        this.action = [];
        this.category = [];
        this.data = [];

        // auto config
        if(config != null){
            for(let i in config)
                    this[i] = config[i];
        }
    }

    toXmlObject(){
        let o = {action:[], category:[], data:[]};
    
        for(let i in this){
            for(let j=0; j<this[i].length; j++){
                o[i].push(this[i][j].toXmlObject());
            }
        }
    
        return o;
    }

    static fromXml(xmlobj){
        let intf = new IntentFilter();

        if(xmlobj.action != null && xmlobj.action instanceof Array){
            for(let i=0; i<xmlobj.action.length; i++){
                intf.action.push(IntentActionCriteria.fromXml(xmlobj.action[i].$));
            }
        }


        if(xmlobj.category != null && xmlobj.category instanceof Array){
            for(let i=0; i<xmlobj.category.length; i++){
                intf.category.push(IntentCategoryCriteria.fromXml(xmlobj.category[i].$));
            }
        }


        if(xmlobj.data != null && xmlobj.data instanceof Array){
            for(let i=0; i<xmlobj.data.length; i++){
                intf.data.push(IntentDataCriteria.fromXml(xmlobj.data[i].$));
            }
        }

        return intf;
    }

    toJsonObject(){
        let o = new Object();

        o.data = [];
        this.data.map(x => o.data.push(x.toJsonObject()));
        o.action = [];
        this.action.map(x => o.action.push(x.toJsonObject()));
        o.category = [];
        this.category.map(x => o.category.push(x.toJsonObject()));

        return o;
    }
}


class AndroidPermissionSdk23
{
    static MODEL = {
        name:"string",
        maxSdkVersion:"integer" 
    }

    constructor(){
        this.name = null;
        this.maxSdkVersion = null; 
    }

    static fromXml(xmlobj){
        let o = new AndroidPermissionSdk23(); 
        
        for(let i in xmlobj){
            if(i.startsWith('android:')){
                o[i.substr(8)] = xmlobj[i]; 
            }else{
                o[i] = xmlobj[i];
            }
        }

        return o;
    }
}

class AndroidGlTexture
{
    constructor(){
        this.name = null;
    }

    static fromXml(xmlobj){
        let o = new AndroidGlTexture();
        o.name = xmlobj['android:name'];
        return o;
    }
}

class AndroidFeature
{
    constructor(){
        this.name = null;
        this.require = null;
        this.glEsVersion = null;
    }

    static fromXml(xmlobj){
        let p = new AndroidFeature();
        
        for(let i in xmlobj){
            if(i.startsWith('android:')){
                p[i.substr(8)] = xmlobj[i]; 
            }else{
                p[i] = xmlobj[i];
            }
        }

        return p;
    }
}


class AndroidActivityAlias
{
    constructor(config=null){
        this.enabled=null;
        this.exported=null;
        this.icon=null;
        this.label=null;
        this.name=null;
        this.permission=null;
        this.targetActivity=null;

        if(config != null){
            for(let i in config)
                if(this[i] !==  undefined)
                    this[i] = config[i];
        }
    }

    toXmlObject(){
        let o = {$:{}};
    
        for(let i in this){
            o.$["android:"+i] = this[i];
        }
    
        return o;
    }

    static fromXml(xmlobj){
        let act = new AndroidActivityAlias();

        for(let i in xmlobj.$){
            if(i.indexOf("android:")>-1)
                act[i.substr(8)] = xmlobj.$[i];
            else
                act[i] = xmlobj.$[i];
        }

        return act;
    }

}


class AndroidInstrumentation
{

    static MODEL = {
        functionalTest:["true" , "false"],
        handleProfiling:["true" , "false"],
        icon:"drawable resource",
        label:"string resource",
        name:"string",
        targetPackage:"string",
        targetProcesses:"string"
    }

    constructor(config=null){
        this.functionalTest=null;
        this.handleProfiling=null;
        this.icon=null;
        this.label=null;
        this.name=null;
        this.targetPackage=null;
        this.targetProcesses=null;
    }

    static fromXml(xmlobj){
        let p = new AndroidInstrumentation();

        for(let i in xmlobj){
            if(i.startsWith('android:')){
                p[i.substr(8)] = xmlobj[i]; 
            }else{
                p[i] = xmlobj[i];
            }
        }

        return p;
    }
}


class AndroidSupportedScreen
{
    static MODEL = {
        resizeable:["true" | "false"],
        smallScreens:["true" | "false"],
        normalScreens:["true" | "false"],
        largeScreens:["true" | "false"],
        xlargeScreens:["true" | "false"],
        anyDensity:["true" | "false"],
        requiresSmallestWidthDp:"integer",
        compatibleWidthLimitDp:"integer",
        largestWidthLimitDp:"integer"
    }
    constructor(){
        this.resizeable=null;
        this.smallScreens=null;
        this.normalScreens=null;
        this.largeScreens=null;
        this.xlargeScreens=null;
        this.anyDensity=null;
        this.requiresSmallestWidthDp=null;
        this.compatibleWidthLimitDp=null;
        this.largestWidthLimitDp=null;
    }

    static fromXml(xmlobj){
        let p = new AndroidSupportedScreen();

        for(let i in xmlobj){
            if(i.startsWith('android:')){
                p[i.substr(8)] = xmlobj[i]; 
            }else{
                p[i] = xmlobj[i];
            }
        }

        return p;
    }
}



class AndroidScreen
{
    constructor(config=null){
        this.screenSize = null;
        this.screenDensity = null;
    }

    static fromXml(xmlobj){
        let p = new AndroidScreen();

        for(let i in xmlobj){
            if(i.startsWith('android:')){
                p[i.substr(8)] = xmlobj[i]; 
            }else{
                p[i] = xmlobj[i];
            }
        }

        return p;
    }
}



  class AndroidConfiguration
  {
      static MODEL = {
        reqFiveWayNav:["true" | "false"],
        reqHardKeyboard:["true" | "false"],
        reqKeyboardType:["undefined" | "nokeys" | "qwerty" | "twelvekey"],
        reqNavigation:["undefined" | "nonav" | "dpad" | "trackball" | "wheel"],
        reqTouchScreen:["undefined" | "notouch" | "stylus" | "finger"]

      }

      constructor(){
        this.reqFiveWayNav=null;
        this.reqHardKeyboard=null;
        this.reqKeyboardType=null;
        this.reqNavigation=null;
        this.reqTouchScreen=null;
      }
  
      static fromXml(xmlobj){
          let p = new AndroidConfiguration();
  
          for(let i in xmlobj){
              if(i.startsWith('android:')){
                  p[i.substr(8)] = xmlobj[i]; 
              }else{
                  p[i] = xmlobj[i];
              }
          }
  
          return p;
      }
  }


class Permission
{
    constructor(config=null){
        this.description = null;
        this.label = null;
        this.name = null;
        this.permissionGroup = null;
        this.protectionLevel = null;
    }

    static fromXml(xmlobj){
        let p = new Permission();

        for(let i in xmlobj){
            if(i.startsWith('android:')){
                p[i.substr(8)] = xmlobj[i]; 
            }else{
                p[i] = xmlobj[i];
            }
        }

        return p;
    }

    toJsonObject(){
        let o = new Object();

        o.name = this.name;
        o.label = this.label;
        o.description = this.description;
        if(this.permissionGroup != null)
            o.permissionGroup = this.permissionGroup.name;
        else
            o.permissionGroup = null;

        return o;
    }
}


class PermissionGroup
{
    constructor(config=null){
        this.description = null;
        this.label = null;
        this.name = null;


        // auto config
        if(config != null){
            for(let i in config)
                if(this[i] !==  undefined)
                    this[i] = config[i];
        }
    }

    static fromXml(xmlobj){
        let p = new PermissionGroup();
        for(let i in xmlobj){
            if(i.startsWith('android:'))
                p[i.substr(8)] = xmlobj[i];
            else
                p[i] = xmlobj[i];
        }
        return p;
    }
}


class PermissionTree
{
    constructor(config=null){
        this.icon = null;
        this.label = null;
        this.name = null;


        // auto config
        if(config != null){
            for(let i in config)
                if(this[i] !==  undefined)
                    this[i] = config[i];
        }
    }

    static fromXml(xmlobj){
        let p = new PermissionTree();
        for(let i in xmlobj){
            if(i.startsWith('android:'))
                p[i.substr(8)] = xmlobj[i];
            else
                p[i] = xmlobj[i];
        }
        return p;
    }
}

/**
 * To represent an activity declared into the Android manifest
 * 
 */
class AndroidActivity
{
    static MODEL = {
        allowEmbedded:["true" , "false"],
        allowTaskReparenting:["true" , "false"],
        alwaysRetainTaskState:["true" , "false"],
        autoRemoveFromRecents:["true" , "false"],
        banner:"drawable resource",
        clearTaskOnLaunch:["true" , "false"],
        colorMode:[ "hdr" , "wideColorGamut"],
        configChanges:["mcc", "mnc", "locale",
                                "touchscreen", "keyboard", "keyboardHidden",
                                "navigation", "screenLayout", "fontScale",
                                "uiMode", "orientation", "density",
                                "screenSize", "smallestScreenSize"],
        directBootAware:["true" , "false"],
        documentLaunchMode:["intoExisting" , "always" ,
                                "none" , "never"],
        enabled:["true" , "false"],
        excludeFromRecents:["true" , "false"],
        exported:["true" , "false"],
        finishOnTaskLaunch:["true" , "false"],
        hardwareAccelerated:["true" , "false"],
        icon:"drawable resource",
        immersive:["true" , "false"],
        label:"string resource",
        launchMode:["standard" , "singleTop" ,
                            "singleTask" , "singleInstance"],
        lockTaskMode:["normal" , "never" ,
                            "if_whitelisted" , "always"],
        maxRecents:"integer",
        maxAspectRatio:"float",
        multiprocess:["true" , "false"],
        name:"string",
        noHistory:["true" , "false"],  
        parentActivityName:"string", 
        persistableMode:["persistRootOnly" , 
                                "persistAcrossReboots" , "persistNever"],
        permission:"string",
        process:"string",
        relinquishTaskIdentity:["true" , "false"],
        resizeableActivity:["true" , "false"],
        screenOrientation:["unspecified" , "behind" ,
                                    "landscape" , "portrait" ,
                                    "reverseLandscape" , "reversePortrait" ,
                                    "sensorLandscape" , "sensorPortrait" ,
                                    "userLandscape" , "userPortrait" ,
                                    "sensor" , "fullSensor" , "nosensor" ,
                                    "user" , "fullUser" , "locked"],
        showForAllUsers:["true" , "false"],
        stateNotNeeded:["true" , "false"],
        supportsPictureInPicture:["true" , "false"],
        taskAffinity:"string",
        theme:"resource or theme",
        uiOptions:["none" , "splitActionBarWhenNarrow"],
        windowSoftInputMode:["stateUnspecified",
                                    "stateUnchanged", "stateHidden",
                                    "stateAlwaysHidden", "stateVisible",
                                    "stateAlwaysVisible", "adjustUnspecified",
                                    "adjustResize", "adjustPan"]
    }

    constructor(config=null){
        // the manifest data are stored here

        this.attr = {};

        this.label = null;
        this.name = null;
        
        this.intentFilters = [];
        this.metadata = null;


        
        // this field contains the associated class
        this.ref = null;

        // auto config
        if(config != null){
            for(let i in config)
                if(this[i] !==  undefined)
                    this[i] = config[i];
        }
    }

    setActivityClass(x){
        this.ref = x;
    }

    getActivityClass(){
        return this.ref;
    }

    setAttributes(attr){
        for(let i in attr){
            if(i.startsWith('android:')){
                this.attr[i.substr(8)] = attr[i]; 
            }else{
                this.attr[i] = attr[i];
            }
        }
    }

    addIntentFilters(filter){
        this.intentFilters.push(filter);
    }

    getAttributes(){
        return this.attr;
    }

    getLabel(){
        return this.label
    }

    getName(){
        return this.name;
    }

    isExported(){
        return (this.attr.exported != null) && (this.attr.exported === true);
    }

    static fromXml(xmlobj){
        let act = new AndroidActivity();

        for(let j in xmlobj){
            switch(j){
                case '$':
                    act.setAttributes(xmlobj.$);
                    act.label = act.attr.label;
                    act.name = act.attr.name;
                    break;
                case 'intent-filter':
                    for(let i=0; i<xmlobj[j].length; i++){
                        act.intentFilters.push(
                            IntentFilter.fromXml(xmlobj[j][i])
                        );
                    }
                    break;
            }
        }

        return act;
    }

    toJsonObject(){
        let o = new Object();

        o.label = this.label;
        o.name = this.name;
        o.attr = this.attr;
        o.intentFilters = [];

        this.intentFilters.map(x => o.intentFilters.push(x.toJsonObject()));

        return o;
    }
}



class AndroidService
{
    
    constructor(config=null){
        // the manifest data are stored here

        this.attr = {};

        this.label = null;
        this.name = null;
        
        this.intentFilters = [];
        this.metadata = null;

        
        // this field contains the associated class
        this.ref = null;

        // auto config
        if(config != null){
            for(let i in config)
                if(this[i] !==  undefined)
                    this[i] = config[i];
        }
    }

    setAttributes(attr){
        for(let i in attr){
            if(i.startsWith('android:')){
                this.attr[i.substr(8)] = attr[i]; 
            }else{
                this.attr[i] = attr[i];
            }
        }
    }

    addIntentFilters(filter){
        this.intentFilters.push(filter);
    }

    getAttributes(){
        return this.attr;
    }

    getLabel(){
        return this.label
    }

    getName(){
        return this.name;
    }

    isExported(){
        return (this.attr.exported != null) && (this.attr.exported === true);
    }

    static fromXml(xmlobj){
        let act = new AndroidService();

        for(let j in xmlobj){
            switch(j){
                case '$':
                    act.setAttributes(xmlobj.$);
                    act.label = act.attr.label;
                    act.name = act.attr.name;
                    break;
                case 'intent-filter':
                    for(let i=0; i<xmlobj[j].length; i++){
                        act.intentFilters.push(
                            IntentFilter.fromXml(xmlobj[j][i])
                        );
                    }
                    break;
            }
        }

        return act;
    }

    toJsonObject(){
        let o = new Object();

        o.label = this.label;
        o.name = this.name;
        o.attr = this.attr;
        o.intentFilters = [];

        this.intentFilters.map(x => o.intentFilters.push(x.toJsonObject()));

        return o;
    }
}

class AndroidReceiver
{
    
    constructor(config=null){
        // the manifest data are stored here

        this.attr = {};

        this.label = null;
        this.name = null;
        
        this.intentFilters = [];
        this.metadata = null;

        
        // this field contains the associated class
        this.ref = null;

        // auto config
        if(config != null){
            for(let i in config)
                if(this[i] !==  undefined)
                    this[i] = config[i];
        }
    }

    setAttributes(attr){
        for(let i in attr){
            if(i.startsWith('android:')){
                this.attr[i.substr(8)] = attr[i]; 
            }else{
                this.attr[i] = attr[i];
            }
        }
    }

    addIntentFilters(filter){
        this.intentFilters.push(filter);
    }

    getAttributes(){
        return this.attr;
    }

    getLabel(){
        return this.label
    }

    getName(){
        return this.name;
    }

    isExported(){
        return (this.attr.exported != null) && (this.attr.exported === true);
    }

    static fromXml(xmlobj){
        let act = new AndroidReceiver();

        for(let j in xmlobj){
            switch(j){
                case '$':
                    act.setAttributes(xmlobj.$);
                    act.label = act.attr.label;
                    act.name = act.attr.name;
                    break;
                case 'intent-filter':
                    for(let i=0; i<xmlobj[j].length; i++){
                        act.intentFilters.push(
                            IntentFilter.fromXml(xmlobj[j][i])
                        );
                    }
                    break;
            }
        }

        return act;
    }

    toJsonObject(){
        let o = new Object();

        o.label = this.label;
        o.name = this.name;
        o.attr = this.attr;
        o.intentFilters = [];

        this.intentFilters.map(x => o.intentFilters.push(x.toJsonObject()));

        return o;
    }
}

class AndroidProvider
{
    
    constructor(config=null){
        // the manifest data are stored here

        this.attr = {};

        this.label = null;
        this.name = null;
        
        this.intentFilters = [];
        this.metadata = null;

        
        // this field contains the associated class
        this.ref = null;

        // auto config
        if(config != null){
            for(let i in config)
                if(this[i] !==  undefined)
                    this[i] = config[i];
        }
    }

    setAttributes(attr){
        for(let i in attr){
            if(i.startsWith('android:')){
                this.attr[i.substr(8)] = attr[i]; 
            }else{
                this.attr[i] = attr[i];
            }
        }
    }

    addIntentFilters(filter){
        this.intentFilters.push(filter);
    }

    getAttributes(){
        return this.attr;
    }

    getLabel(){
        return this.label
    }

    getName(){
        return this.name;
    }

    isExported(){
        return (this.attr.exported != null) && (this.attr.exported === true);
    }

    static fromXml(xmlobj){
        let act = new AndroidProvider();

        for(let j in xmlobj){
            switch(j){
                case '$':
                    act.setAttributes(xmlobj.$);
                    act.label = act.attr.label;
                    act.name = act.attr.name;
                    break;
                case 'intent-filter':
                    for(let i=0; i<xmlobj[j].length; i++){
                        act.intentFilters.push(
                            IntentFilter.fromXml(xmlobj[j][i])
                        );
                    }
                    break;
            }
        }

        return act;
    }

    toJsonObject(){
        let o = new Object();

        o.label = this.label;
        o.name = this.name;
        o.attr = this.attr;
        o.intentFilters = [];

        this.intentFilters.map(x => o.intentFilters.push(x.toJsonObject()));

        return o;
    }
}


class AndroidApplication
{
    static MODEL = {
        allowTaskReparenting:["true" | "false"],
        allowBackup:["true" | "false"],
        allowClearUserData:["true" | "false"],
        backupAgent:"string",
        backupInForeground:["true" | "false"],
        banner:"drawable resource",
        debuggable:["true" | "false"],
        description:"string resource",
        directBootAware:["true" | "false"],
        enabled:["true" | "false"],
        extractNativeLibs:["true" | "false"],
        fullBackupContent:"string",
        fullBackupOnly:["true" | "false"],
        hasCode:["true" | "false"],
        hardwareAccelerated:["true" | "false"],
        icon:"drawable resource",
        isGame:["true" | "false"],
        killAfterRestore:["true" | "false"],
        largeHeap:["true" | "false"],
        label:"string resource",
        logo:"drawable resource",
        manageSpaceActivity:"string",
        name:"string",
        networkSecurityConfig:"xml resource",
        permission:"string",
        persistent:["true" | "false"],
        process:"string",
        restoreAnyVersion:["true" | "false"],
        requiredAccountType:"string",
        resizeableActivity:["true" | "false"],
        restrictedAccountType:"string",
        supportsRtl:["true" | "false"],
        taskAffinity:"string",
        testOnly:["true" | "false"],
        theme:"resource or theme",
        uiOptions:["none" | "splitActionBarWhenNarrow"],
        usesCleartextTraffic:["true" | "false"],
        vmSafeMode:["true" | "false"]
    }

    constructor(config=null){

        this.attr = {};


        this.activities = [];
        this.activityAliases = [];
        this.launcherActivities = [];
        this.services = [];
        this.receivers = [];
        this.providers = [];

        this.usesLibraries = [];
        this.metaData = [];

        if(config!=null)
            for(let i in config)
                if(this[i] !== undefined)
                    this[i] = config[i];
    }

    static fromXml(xmlobj){
        let app = new AndroidApplication();

        for(let i in xmlobj.$){
            if(i.startsWith('android:')){
                app.attr[i.substr(8)] = xmlobj.$[i]; 
            }else{
                app.attr[i] = xmlobj.$[i];
            }
        }

        for(let j in xmlobj){
            switch(j){
                case 'activity':
                    for(let i=0; i<xmlobj.activity.length; i++){
                        app.activities.push(AndroidActivity.fromXml(xmlobj.activity[i]));
                    }
                    break;
                case 'services':
                    for(let i=0; i<xmlobj.service.length; i++){
                        app.services.push(AndroidService.fromXml(xmlobj.service[i]));
                    }
                    break;
                case 'receiver':
                    for(let i=0; i<xmlobj.receiver.length; i++){
                        app.receivers.push(AndroidReceiver.fromXml(xmlobj.receiver[i]));
                    }
                    break;
                case 'provider':
                    for(let i=0; i<xmlobj.provider.length; i++){
                        app.providers.push(AndroidProvider.fromXml(xmlobj.provider[i]));
                    }
                    break;
                case 'meta-data':
                    for(let i=0; i<xmlobj['meta-data'].length; i++){
                        app.metaData.push(xmlobj['meta-data'][i].$);
                    }
                    break;
                case 'uses-library':
                    for(let i=0; i<xmlobj['uses-library'].length; i++){
                        app.usesLibraries.push(xmlobj['uses-library'][i].$);
                    }
                    break;
            }
        }


        return app;
    }
}


class AndroidManifest
{
    constructor(config=null){

        this.attributes = {};

        this.usesPermissions = [];
        this.permissions = [];
        this.permissionTrees = [];
        this.permissionGroups = [];
        this.instrumentation = null;
        this.usesPermissionsSdk23 = null;
        
        this.usesSdk = {
            'android:minSdkVersion': null,
            'android:targetSdkVersion': null,
        };

        this.usesConfiguration = null;
        this.usesFeatures = [];

        this.supportsScreens = null;
        this.compatibleScreens = [];
        this.supportsGlTextures = [];
        this.application = null;

        if(config!=null){
            this.setup(config);
        }
            
    }

    static fromXml(config){
        let self = new AndroidManifest();
        // init manifest attributes 
        for(let i in config){
            switch(i){
                case '$':
                    self.setAttributes(config['$']);
                    break;
                case 'uses-sdk':
                    config['uses-sdk'].map(function(k){
                        self.usesSdk = k.$;
                    });
                    break;
                case 'uses-permission':
                    config['uses-permission'].map(function(k){
                        self.usesPermissions.push(Permission.fromXml(k.$));
                    });
                    break;
                case 'permission':
                    config['permission'].map(function(k){
                        self.permissions.push(Permission.fromXml(k.$));
                    });
                    break;
                case 'permission-group':
                    config['permission-group'].map(function(k){
                        self.permissionGroup.push(PermissionGroup.fromXml(k.$));
                    });
                    break;
                case 'permission-tree':
                    config['permission-tree'].map(function(k){
                        self.permissionTrees.push(PermissionTree.fromXml(k.$));
                    });
                    break;
                case 'uses-feature':
                    config['uses-feature'].map(function(k){
                        self.usesFeatures.push(AndroidFeature.fromXml(k.$));
                    });
                    break;
                case 'supports-gl-texture':
                    config['supports-gl-texture'].map(function(k){
                        self.supportsGlTextures.push(AndroidGlTexture.fromXml(k.$));
                    });
                    break;
                case 'compatible-screens':
                    config['compatible-screens'].map(function(k){
                        self.compatibleScreens.push(AndroidScreen.fromXml(k.$));
                    });
                    break;
                case 'supports-screens':
                if(self.supportsScreens===null) self.supportsScreens = [];
                    config['supports-screens'].map(function(k){
                        self.supportsScreens.push(AndroidSupportedScreen.fromXml(k.$));
                    });
                    break;
                case 'uses-configuration':
                    if(self.usesConfiguration===null) self.usesConfiguration = [];

                    config['uses-configuration'].map(function(k){
                        self.usesConfiguration.push(AndroidConfiguration.fromXml(k.$));
                    });
                    break;
                case 'uses-permission-sdk-23':
                    if(self.usesPermissionsSdk23===null) self.usesPermissionsSdk23 = [];

                    config['uses-permission-sdk-23'].map(function(k){
                        self.usesPermissionsSdk23.push(AndroidPermissionSdk23.fromXml(k.$));
                    });
                    break;
                case 'instrumentation':
                    if(self.instrumentation===null) self.instrumentation = [];

                    config['instrumentation'].map(function(k){
                        self.instrumentation.push(AndroidInstrumentation.fromXml(k.$));
                    });
                    break;
                case 'application':
                    if(config[i] instanceof AndroidApplication){
                        //console.log(config[i]);
                        self.application = config[i];
                    }else{
                        // console.log(config[i]);
                        self.application = AndroidApplication.fromXml(config[i][0]);
                    }
                    break;x
            }
        }

        return self;
    }

    toXml(){
        let o = new Object();

        o.$ = {};
        for(let i in this.attributes){
            o.$[i] = this.attributes[i];
        }

        if(this.usesPermissions.length > 0){
            o['uses-permission'] = [];
            this.usesPermissions.map(perm => {
                o['uses-permission'].push(perm.toXml());
            });
        }

        if(this.permissions.length > 0){
            o['permission'] = [];
            this.permissions.map(perm => {
                o['permission'].push(perm.toXml());
            });
        }

        if(this.permissionGroups.length > 0){
            o['permission-group'] = [];
            this.permissionGroups.map(perm => {
                o['permission-group'].push(perm.toXml());
            });
        }

        if(this.permissionTrees.length > 0){
            o['permission-tree'] = [];
            this.permissionTrees.map(perm => {
                o['permission-tree'].push(perm.toXml());
            });
        }

        if(this.instrumentation != null && this.instrumentation.length > 0){
            o['instrumentation'] = [];
            this.instrumentation.map(perm => {
                o['instrumentation'].push(perm.toXml());
            });
        }
        
        if(this.usesPermissionsSdk23 != null && this.usesPermissionsSdk23.length > 0){
            o['uses-permission-sdk-23'] = [];
            this.usesPermissionsSdk23.map(perm => {
                o['uses-permission-sdk-23'].push(perm.toXml());
            });
        }

        if(this.usesConfiguration != null && this.usesConfiguration.length > 0){
            o['uses-configuration'] = [];
            this.usesConfiguration.map(perm => {
                o['uses-configuration'].push(perm.toXml());
            });
        }

        if(this.usesFeatures != null && this.usesFeatures.length > 0){
            o['uses-feature'] = [];
            this.usesFeatures.map(perm => {
                o['uses-feature'].push(perm.toXml());
            });
        }
        
        if(this.usesSdk != null && this.usesSdk.length > 0){
            o['uses-sdk'] = [];        
            o['uses-sdk'].push(this.usesSdk);    
        }

        if(this.supportsScreens != null && this.supportsScreens.length > 0){
            o['supports-screens'] = [];
            this.supportsScreens.map(perm => {
                o['supports-screens'].push(perm.toXml());
            });
        }
        if(this.compatibleScreens != null && this.compatibleScreens.length > 0){
            o['compatible-screens'] = [];
            this.compatibleScreens.map(perm => {
                o['compatible-screens'].push(perm.toXml());
            });
        }
        if(this.supportsGlTextures != null && this.supportsGlTextures.length > 0){
            o['supports-gl-texture'] = [];
            this.supportsGlTextures.map(perm => {
                o['supports-gl-texture'].push(perm.toXml());
            });
        }
        if(this.usesFeatures != null && this.usesFeatures.length > 0){
            o['uses-feature'] = [];
            this.usesFeatures.map(perm => {
                o['uses-feature'].push(perm.toXml());
            });
        }

        o.application = this.application.toXml();

        return o;
    }

    setAttributes(attrs){
        this.attributes = attrs;
    }

    getAttrVersionCode(){
        return this.attributes['android:versionCode'];
    }
    
    getAttrVersionName(){
        return this.attributes['android:versionName'];
    }

    getAttrPackage(){
        return this.attributes['package'];
    }

    getAttrPlatformBuildVersionCode(){
        return this.attributes['platformBuildVersionCode'];
    }

    getAttrPlatformBuildVersionName(){
        return this.attributes['platformBuildVersionName'];
    }
    
    getAttrXmlNS(){
        return this.attributes['xmlns:android'];
    }

    getMinSdkVersion(){
        return this.usesSdk['android:minSdkVersion'];
    }

    getTargetSdkVersion(){
        return this.usesSdk['android:targetSdkVersion'];
    }

    /**
     * To get the Application description as declared into the manifest
     * @returns {AndroidApplication} The manifest's description of the application
     */
    getApplication(){
        return this.application;
    }
    
    /**
     * To get the permissions of the applciaton as declared into the manifest
     * 
     */
    getPermissions(){
        return this.permissions;
    }

    /**
     * To check is the application require the given permission
     * @param {AndroidPermission | String} perm The permission to search
     * @returns {Boolean} Return TRUE if the given permission is required, else FALSE 
     */
    requirePermission(perm){
        let res = false;
        if(perm instanceof Permission){
            this.usesPermissions.map(function(p){
                if(p.getName()===perm.getName())
                    res = true;
            })
        }else{
            this.usesPermissions.map(function(p){
                if(p.getName()===perm)
                    res = true;
            })
        }
        return res;
    }

    
}

module.exports = {

    Activity: AndroidActivity,
    Receiver: AndroidReceiver,
    Service: AndroidService,
    Provider: AndroidProvider,
    Application: AndroidApplication,

    Manifest: AndroidManifest,

    Feature: AndroidFeature,

    Permission: Permission,
    PermissionGroup: PermissionGroup,

    IntentFilter: IntentFilter,
    IntentDataCriteria: IntentDataCriteria,
    IntentActionCriteria: IntentActionCriteria,
    IntentCategoryCriteria: IntentCategoryCriteria,
};