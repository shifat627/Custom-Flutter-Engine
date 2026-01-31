// Pointer compression ,
// Compressed pointers are 32bit offset , that's LSB is set to 1
// To decompress, All we have to (heap base address + (compressed_pointer & 0xfffffff0)) or (heap base address + (compressed_pointer - 1 ))
// Argument pointers are not compressed

// SMI
// SMI are numbers , those are left shifted by ( num << 1) and their LSB is set to 0.
// 
// In dart Everything is OBJECT

// Finding a object from Global pool address in heap in x64
// We hook any address in the code using frida
// after hooking , we locate where that object's compress pointer is stored , by compressed_pointer = (r15 + pp_index).readPointer()
// if ((r15 + pp_index).readU32() & 1 === 1) , it is compressed pointer
// to decompress it , we at first need heap base , which found by heap_base = (r14 + 0x48).readPointer()
// then we add object_pointer = heap_base + (compressed_pointer & 0xfffffff0)

//Parsing object
// every object in dart has Tag/marker (4 bytes) at beginning of Object
// TO get tag , Tag = object_pointer.readU32()
// need to get classID from tag , to do that cid = (Tag >> 12) & 0xfffff
// we will use classID to identify if it string , list , map etc. For example if it is tag => 92 or tag <= 96> , it is string


function getObjectPointer(pp_offset,context){
    var HEAP_BASE_OFFSET = 0x48; // it is located in runtime/compiler/runtime_offsets_extracted.h , here offsets for all architecture can be found.From here I only extracted for x64
    var str_obj_compressed_pointer = (context.r15.add(pp_offset)).readU32()
    if ((str_obj_compressed_pointer & 1) === 1){
        str_obj_compressed_pointer = (str_obj_compressed_pointer & 0xfffffff0);
        var heap_base_pointer = context.r14.add(HEAP_BASE_OFFSET).readPointer()
        return heap_base_pointer.add(str_obj_compressed_pointer)

        
    }

    return (context.r15.add(pp_offset)).readPointer()

}



function getSMI(num){
    if ((num & 1) === 0){
        return num >> 1;
    }

    return num
}

function ParseObj(obj_addr){
    var tag = obj_addr.readU32()
    var classID = ((tag >> 12) & 0xfffff)

    if (classID >= 92 || classID <= 96){
        console.log('[!]String Object is Detected')
        var str_len = getSMI(obj_addr.add(0x8).readU64())
        var str_data = obj_addr.add(0x10).readCString()
        return {'result': [str_len,str_data]}
    }
    // In You can Implement Handling other object like list ,array , map , instance etc.
    return null
}


Java.perform(()=>{

    var address = Process.findModuleByName("libapp.so").base;
    var instruction_offset = 0x005902e9;
    var pp_offset = 0xf417;

    Interceptor.attach(address.add(instruction_offset),{
        onEnter(args){
            var str_obj = getObjectPointer(pp_offset,this.context)
            var result = ParseObj(str_obj)
            if (result != null){
                console.log(`String Length : ${result['result'][0]}`)
                console.log(`String: ${result['result'][1]}`)
            }

        },
        onLeave(ret){

        }
    })

})
