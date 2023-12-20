# What is BVFinder?

BVFinder is a baseband firmware static vulnerability prototype detection tool developed based on [BinAbsInspector](https://github.com/KeenSecurityLab/BinAbsInspector/tree/main). It identifies a vulnerability by locating whether a predefined sensitive memory operation is tainted by any attacker-controllable input. Specifically, to reach high automation and preciseness, it made two key improvements: a semantic-based taint source identification and an enhanced taint propagation. The former employs semantic search techniques to identify registers and memory offsets that carry attacker-controllable inputs. This is achieved by matching the inputs to their corresponding message and data types using textual features and addressing patterns within the assemblies.On the other hand, the latter technology guarantees effective taint propagation by employing additional indirect call resolution algorithms.

# Installation

- Install Ghidra 10.1.5 according to [Ghidra's documentation](https://github.com/NationalSecurityAgency/ghidra#install)

   - Install [ShannonLoader](https://github.com/grant-h/ShannonBaseband/tree/master/reversing/ghidra/ShannonLoader) to load samsung shannon firmware

- Download the extension zip file from this repo.
- Start Ghidra and use the "Install Extensions" dialog (File -> Install Extensions...).
- Press the + button in the upper right corner.
- Select the zip file in the file browser, then restart Ghidra.

# Usage

You can run BVFinder in GUI mode.

1. Run Ghidra and import the target binary into a project
2. Analyze the binary firmware according to the description of  [ShannonLoader](https://github.com/grant-h/ShannonBaseband/tree/master/reversing/ghidra/ShannonLoader)  
3. When the analysis is done, open Window -> Script Manager and find BinAbsInspector.java
4. Double-click on BinAbsInspector.java entry, then it will run the default analysis.
5. When the analysis is done, you can see the out put on ghidra's console.



## Testing

You can use or test the BVFinder interface by modifying BinAbsInspector.java. The original version we currently release supports the following functions:

- Collect initial binary variables and taint sources.
- Filter initial taint source variables through code semantics (access mode of base+offset).
- Filter initial taint source variables through log information and 3gpp protocol specifications (use logStringMatch.py script).
- Solve indirect calls based on inter-procedural data flow analysis
- Detect buffer overflow or out-of-bounds access bugs caused by memory operation functions and loops.

You can perform the test of the above function by modifying the following code in BinAbsInspector.java.

> **NOTE**: The default settings of the script were tested on firmware version CP_G960FXXS2BRH8, which can be downloaded in the link given below.

```java
    protected boolean analyze() {
        // ------- All APIs -------
        Function f = GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x40d46ee6));
        Set<Address> addresses = new HashSet();
        Set<Address> filtered = new HashSet();

        //** Collect Initial Taint Sources.
        BVFinder.getInitBinaryVars(f, addresses);
        println("[+] Number of Initial binary variable used address:"+addresses.size()+"");
        int initialTsources = BVFinder.tagTaintSource(addresses);
        println("[+] Number of Initial Taint Sources： "+initialTsources+"");

        //** filtered by DataRefer
        BVFinder.dataReference(addresses, filtered);
        println("[+] Number of Initial Taint Sources before filtered: " + BVFinder.tainted.size());
        println("[+] Number of Initial Taint Sources after  filtered: " + filtered.size());

        //** Collect Debug Strings.
        // BVFinder.getMsgVariabledDebugInfo(addresses,"D:\\debugString1111111111111.json");
        // use python script to filter this json file.
        // BVFinder.tGlobalvar.add(GlobalState.flatAPI.toAddr(address));

        //** Indirect Call resolving.
        GlobalState.icall = 0;
        if(GlobalState.icall == 1){
            Address fcontainsicall = GlobalState.flatAPI.toAddr(0x40d46abc);
            BVFinder.resolveIncalls(fcontainsicall);
            for(Map.Entry<Address, Address> entry: GlobalState.icall_taints.entrySet()){
                println(entry.getKey().toString() + "  " + entry.getValue() + "");
            }
            return analyzeFromAddress(fcontainsicall);
        }

        //** Static Taint Analysis.
        GlobalState.icall = 0;
        // Check memcpy-like functions.
        GlobalState.check_funcs = false;
        if(GlobalState.check_funcs){
            // mm_CopyBufferBytes
            Function memcpy = GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x40e73932));
            BasebandMemcpy.addstaticSymbols(memcpy.getName());
            addresses.clear();
            addresses.add(GlobalState.flatAPI.toAddr(0x42b162d4));
            BVFinder.tagTaintSource(addresses);
            Address fcontainsicall = GlobalState.flatAPI.toAddr(0x40779790);
            return analyzeFromAddress(fcontainsicall);
        }
        // Check loops.
        GlobalState.check_loop = true;
        if(GlobalState.check_loop){
            addresses.clear();
            addresses.add(GlobalState.flatAPI.toAddr(0x42b3d614));
            BVFinder.tagTaintSource(addresses);
            Address fcontainsicall = GlobalState.flatAPI.toAddr(0x408a8f86);
            boolean status = analyzeFromAddress(fcontainsicall);
            for(Address address: BVFinder.reported_loop_addr){
                println("Potential parsing IE via loop at" + " 0x" + address);
            }
            return status;
        }
```



# DataSet

- [FirmWire Dataset](https://zenodo.org/record/6516030/)
- [Third party website](https://www.sammobile.com/firmwares)



# Stable version

We plan to release a stable version of the code with more features in the near future! 

# Acknowledgement

We use Ghidra and BinAbsInspector as our disassembly tool and data flow analysis framework. Here we would like to thank them for their great work!
