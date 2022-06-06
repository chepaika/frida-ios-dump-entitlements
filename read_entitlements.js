Module.ensureInitialized('Foundation');


function pad(str, n) {
    return Array(n-str.length+1).join("0")+str;
}

function swap32(value) {
    value = pad(value.toString(16),8)
    var result = "";
    for(var i = 0; i < value.length; i=i+2){
        result += value.charAt(value.length - i - 2);
        result += value.charAt(value.length - i - 1);
    }
    return parseInt(result,16)
}

function getExportFunction(name, ret, args, is_system = false) {
    var symbol_ptr;
    symbol_ptr = Module.findExportByName(null, name);
    if (symbol_ptr === null) {
        console.error("Cannot find " + name);
        return null;
    } 
    var funclet = is_system ? new SystemFunction(symbol_ptr, ret, args) : new NativeFunction(symbol_ptr, ret, args);
    if (typeof funclet === "undefined") {
        console.error("Invalid input format of function " + name);
        return null;
    }
    return funclet;
}

function getExportData(name) {
    var symbol_ptr;
    symbol_ptr = Module.findExportByName(null, name);
    if (symbol_ptr === null) {
        console.error("Cannot find " + name);
        return null;
    } 

    var datalet = Memory.readPointer(symbol_ptr);
    if (typeof datalet === "undefined") {
        console.error("Cannot get data from " + name);
        return null;
    }
    return datalet;
}

function getEntitlementsFromSlot(entitlements_slot_ptr) {
    var CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171;

    var entitlements_magic = swap32(entitlements_slot_ptr.readU32());
    if (entitlements_magic != CSMAGIC_EMBEDDED_ENTITLEMENTS)
    {
        console.error("Entitlements magic is " + entitlements_magic + 
                    " but should be " + CSMAGIC_EMBEDDED_ENTITLEMENTS);
        return null;
    }

    var entitlements_size = swap32(entitlements_slot_ptr.add(4).readU32()) - 8;
    var entitlements = entitlements_slot_ptr.add(8).readUtf8String(entitlements_size);
    return entitlements;
}

function getEntitlementsByPid(pid) {
    Module.ensureInitialized("libsystem_kernel.dylib")

    var CS_OPS_ENTITLEMENTS_BLOB = 0x7;
    var ERANGE = 34;

    var csops = getExportFunction("csops", "int", ["int", "uint", "pointer", "ulong"], true)
    if (csops == null) {
        console.error("Can't find csops function for read entitlements")
        return null;
    }

    var strerror = getExportFunction("strerror", "pointer", ["int"]);
    if (strerror == null) {
        console.error("Cann't find strerror function for debug process of read entitlements")
    }
    
    var buffer_size_increment = 1024;
    var buffer_size = buffer_size_increment;
    while(true){
        var buffer = Memory.alloc(buffer_size);
        var result = csops(pid, CS_OPS_ENTITLEMENTS_BLOB, buffer, buffer_size);
        
        if (result.value == -1) {
            if (result.errno = ERANGE) {
                buffer_size += buffer_size_increment;
                continue;
            } else {
                console.error("Cann't get entitlements with error: " + strerror(result.errno).readCString())
                return null
            }
        }

        var entitlements = getEntitlementsFromSlot(buffer);
        if(entitlements == null) {
            console.error("Cann't get entitlemnts from slot");
            return null;
        }
    
        return entitlements;
    }
}

function SignatureInfo(offset, size) {
    this.offset = offset;
    this.size = size;
}

function getSignatureInfoFromModule(module) {
    var FAT_MAGIC = 0xcafebabe;
    var FAT_CIGAM = 0xbebafeca;
    var MH_MAGIC = 0xfeedface;
    var MH_CIGAM = 0xcefaedfe;
    var MH_MAGIC_64 = 0xfeedfacf;
    var MH_CIGAM_64 = 0xcffaedfe;
    var LC_CODE_SIGNATURE = 0x1d;


    var mod_base = module.base
    var size_of_mach_header = 0;
    var magic = mod_base.readU32();

    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        size_of_mach_header = 28;
    }else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        size_of_mach_header = 32;
    }else if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        console.error("Main module is FAT(( But we cann't work with FAT");
        return null;
    }

    var signature_offset = 0;
    var signature_size = 0;
    var ncmds = mod_base.add(16).readU32();
    var off = size_of_mach_header;
    for (var i = 0; i < ncmds; i++) {
        var cmd = mod_base.add(off).readU32();
        var cmdsize = mod_base.add(off + 4).readU32();
        if (cmd == LC_CODE_SIGNATURE) {
            signature_offset = mod_base.add(off + 8).readU32();
            signature_size = mod_base.add(off + 12).readU32();
            off += cmdsize;
            break;
        }
        off += cmdsize;
    }

    if (signature_offset == 0 || signature_size == 0)
    {
        console.error("No signature found in mine module " + module.path)
        return null;
    }

    return new SignatureInfo(signature_offset, signature_size)
}

function mapSignatureToMemory(module, signatureInfo) {
    var O_RDONLY = 0;
    var O_WRONLY = 1;
    var O_RDWR = 2;
    var O_CREAT = 512;

    var SEEK_SET = 0;
    var SEEK_CUR = 1;
    var SEEK_END = 2;

    var open = getExportFunction("open", "int", ["pointer", "int", "int"]);
    var read = getExportFunction("read", "int", ["int", "pointer", "int"]);
    var lseek = getExportFunction("lseek", "int64", ["int", "int64", "int"]);
    var close = getExportFunction("close", "int", ["int"]);

    if (open == null || read == null || lseek == null || close == null) {
        console.error("Cann't find open/read/lseek/close function for mapping signature");
        return null;
    }

    var main_module_path = Memory.allocUtf8String(main_module.path);
    var main_module_file = open(main_module_path, O_RDONLY, 0);
    
    if (main_module_file == -1) {
        console.error("Can not open file: " + main_module.path);
        return null;
    }

    if (lseek(main_module_file, signatureInfo.offset,SEEK_SET) != signatureInfo.offset)
    {
        console.error("Can not set cursor in file to signature super blob");
        close(main_module_file);
        return null;
    }

    var signature_buffer = Memory.alloc(signatureInfo.size);
    var readed_size = read(main_module_file, signature_buffer, signatureInfo.size);
    close(main_module_file);

    if (readed_size != signatureInfo.size) {
        console.error("Signature size is " + signatureInfo.size + " but readed only " + readed_size);
        return null;
    }

    return signature_buffer;
}

function getEntitlementsFromCS(cs_buffer){
    var CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
    var CSSLOT_ENTITLEMENTS = 0x5;

    var superblob_signature = swap32(cs_buffer.readU32());
    if (superblob_signature != CSMAGIC_EMBEDDED_SIGNATURE)
    {
        console.error("Signature super blob magic is " + superblob_signature + 
                        " but expected " +  CSMAGIC_EMBEDDED_SIGNATURE);
        return null;
    }

    var super_blob_header_size = 4 * 3;
    var blob_index_size = 4 * 2;
    var blob_count = swap32(cs_buffer.add(4*2).readU32())
    
    var entitlement_slot_offset = 0;
    for (var i = 0; i < blob_count; i++) {
        var current_blob_offset = super_blob_header_size + i*blob_index_size
        var current_blob_type = swap32(cs_buffer.add(current_blob_offset).readU32());
        if (current_blob_type == CSSLOT_ENTITLEMENTS) {
            entitlement_slot_offset = swap32(cs_buffer.add(current_blob_offset + 4).readU32());
        }
    }

    if (entitlement_slot_offset == 0) {
        console.error("Can't find entitlements in code signature");
        return null;
    }

    var entitlements = getEntitlementsFromSlot(cs_buffer.add(entitlement_slot_offset));
    if(entitlements == null) {
        console.error("Cann't get entitlemnts from slot");
        return null;
    }

    return entitlements;
}

function getEntitlementsFromModule(module)
{
    var signature_info = getSignatureInfoFromModule(module);
    if (signature_info == null) {
        console.error("Can't get signature info");
        return null;
    }

    var signature_buffer = mapSignatureToMemory(module, signature_info);
    if (signature_buffer == null) {
        console.error("Can't map code signature to memory");
        return null;
    }

    var entitlements = getEntitlementsFromCS(signature_buffer);
    if (entitlements == null) {
        console.error("Can't get intitlements from code sigrnature");
        return null;
    }

    return entitlements;
}

function getAppKeychainGroups(entitlements) {
    var NSUTF8StringEncoding = 4;

    var ns_str_ent = ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String(entitlements));
    var entitlements_as_data = ns_str_ent.dataUsingEncoding_(NSUTF8StringEncoding);

    //NSPropertyListFormat are C enum)) so for arm64 -> 8 byte;
    var format = Memory.alloc(8)

    var error = ObjC.classes.NSString;
    var persed_entitlements = ObjC.classes.NSPropertyListSerialization.propertyListWithData_options_format_error_(entitlements_as_data, 0, format, error)

    if (persed_entitlements == null) {
        console.error("Can't parse entitlements with a error: " + error);
        return null;
    }

    if (!persed_entitlements.isKindOfClass_(ObjC.classes.NSDictionary)) {
        console.error("Invalid entitlements format");
        return null;
    }

    var result = [];

    var app_identifier = String(persed_entitlements.objectForKey_("application-identifier"));
    if (app_identifier == null) {
        console.error("Invalid entitlements. Can't find `application-identifier`");
        return null;
    }
    result.push(app_identifier);

    var keychain_groups = persed_entitlements.objectForKey_("keychain-access-groups");
    if (keychain_groups != null) {
        var count = keychain_groups.count().valueOf();
        for(var i = 0; i < count; i++) {
            result.push(String(keychain_groups.objectAtIndex_(i)));
        } 
    }

    var application_groups = persed_entitlements.objectForKey_("com.apple.security.application-groups");
    if (application_groups != null) {
        var count = application_groups.count().valueOf();
        for(var i = 0; i < count; i++) {
            result.push(String(application_groups.objectAtIndex_(i)));
        } 
    }

    return result;
}

//    main_module = Process.enumerateModules()[0]

function main() {
    console.log("Try get entitlements by pid")
    var entitlements = getEntitlementsByPid(Process.id);
    if (entitlements == null) {
        console.warn("Cann't get entitlements by pid");
        console.log("Try get entitlements from binary file")
        entitlements = getEntitlementsFromModule(Process.enumerateModules()[0])
        if (entitlements == null) {
            console.warn("Cann't get entitlements from binary file");
            console.error("Cann't get entitlements at all");
            send("");
            return;
        }
    }

    console.log("Try get keychain groups from entitlements");
    var keychain_groups = getAppKeychainGroups(entitlements);
    if (keychain_groups == null) {
        console.error("Cann't get keychain groups from entitlements");
        send("");
        return;
    }

    console.log("Keychain groups are " + keychain_groups)
    send(keychain_groups);
    return;
}

main();