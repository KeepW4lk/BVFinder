//
//@author Tencent KeenLab and enhanced by n3vv
//@category Analysis
//@keybinding
//@menupath Analysis.BinAbsInspector
//@toolbar logo.gif


import com.bai.checkers.BVFinder;
import com.bai.checkers.CheckerManager;
import com.bai.env.funcs.FunctionModelManager;
import com.bai.env.funcs.externalfuncs.BasebandMemcpy;
import com.bai.solver.InterSolver;
import com.bai.util.*;
import com.bai.util.Config.HeadlessParser;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import org.apache.commons.collections4.map.HashedMap;
import org.apache.commons.lang3.StringUtils;
import com.bai.env.Context;


import java.awt.*;
import java.util.List;
import java.util.*;



public class RQ3 extends GhidraScript {

    protected boolean prepareProgram() {
        GlobalState.jumpedFunctions = new String[4];
        GlobalState.jumpedFunctions[0] = "log";
        GlobalState.jumpedFunctions[1] = "SAECOMM_Utility__CurrentStack";
        GlobalState.jumpedFunctions[2] = "Backup";
        GlobalState.jumpedFunctions[3] = "FUN_413fe778";
        GlobalState.state = this.state;
        GlobalState.currentProgram = this.currentProgram;
        GlobalState.decompInterface = new DecompInterface();
        GlobalState.assembler = Assemblers.getAssembler(GlobalState.currentProgram);
        GlobalState.decompInterface.setOptions(new DecompileOptions());
        GlobalState.decompInterface.openProgram(GlobalState.currentProgram);
        GlobalState.flatAPI = this;
        GlobalState.icall_taints = new HashedMap();
        GlobalState.basicBlockModel = new BasicBlockModel(GlobalState.currentProgram);
        GlobalState.listing = this.currentProgram.getListing();
        Language language = GlobalState.currentProgram.getLanguage();
        return language != null;
    }

    protected boolean analyzeFromMain() {
        List<Function> functions = GlobalState.currentProgram.getListing().getGlobalFunctions("main");
        if (functions == null || functions.size() == 0) {
            return false;
        }
        Function entryFunction = functions.get(0);
        if (entryFunction == null) {
            Logging.error("Cannot find entry function");
            return false;
        }
        Logging.info("Running solver on \"" + entryFunction + "()\" function");
        InterSolver solver = new InterSolver(entryFunction, true);
        solver.run();
        return true;
    }

    protected boolean analyzeFromAddress(Address entryAddress) {
        Function entryFunction = GlobalState.flatAPI.getFunctionAt(entryAddress);
        if (entryAddress == null) {
            Logging.error("Could not find entry function at " + entryAddress);
            return false;
        }
        Logging.info("Running solver on \"" + entryFunction + "()\" function");
        println("Running solver on \"" + entryFunction + "()\" function");
        InterSolver solver = new InterSolver(entryFunction, false);
        solver.run();
        Context.resetPool();
        System.gc();
        return true;
    }

    /**
     * Start analysis with following steps:
     * 1. Start from specific address if user provided, the address must be the entrypoint of a function.
     * 2. Start from "main" function if step 1 fails.
     * 3. Start from "e_entry" address from ELF header if step 2 fails.
     * @return
     */
    protected boolean analyze() {
        Set<Address> addresses = new HashSet();
        GlobalState.check_funcs = true;
        Function memcpy = GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x40e73932)); // add sink function
        BasebandMemcpy.addstaticSymbols(memcpy.getName());
        addresses.clear();
        addresses.add(GlobalState.flatAPI.toAddr(0x416050d4));  // add taint source
        addresses.add(GlobalState.flatAPI.toAddr(0x416050e4));  // add taint source
        BVFinder.tagTaintSource(addresses);
        Address fcontainsicall = GlobalState.flatAPI.toAddr(0x40779790); // set start point
        return analyzeFromAddress(fcontainsicall);
    }

    private void guiProcessResult() {
        if (!GlobalState.config.isGUI()) {
            return;
        }
        String msg = "Analysis finish!\n Found " + Logging.getCWEReports().size() + " CWE Warning.";
        GlobalState.ghidraScript.popup(msg);
        Logging.info(msg);
        for (CWEReport report : Logging.getCWEReports().keySet()) {
            GlobalState.ghidraScript.setBackgroundColor(report.getAddress(), Color.RED);
            GlobalState.ghidraScript.setEOLComment(report.getAddress(), report.toString());
            Logging.warn(report.toString());
        }
    }

    @Override
    public void run() throws Exception {
        GlobalState.config = new Config();
        // bvfinder mode
        boolean run_module = true;
        if (isRunningHeadless()) {
            String allArgString = StringUtils.join(getScriptArgs()).strip();
            GlobalState.config = HeadlessParser.parseConfig(allArgString);
        } else if(!run_module){
            GlobalState.ghidraScript = this;
            GlobalState.config = new Config();
            GlobalState.config.setGUI(true);
            ConfigDialog dialog = new ConfigDialog(GlobalState.config);
            dialog.showDialog();
            if (!dialog.isSuccess()) {
                return;
            }
        } else {
            GlobalState.config.setK(6);
            GlobalState.config.setCallStringK(6);
            GlobalState.config.setZ3TimeOut(1000);
            GlobalState.config.setTimeout(-1);
            GlobalState.config.setEnableZ3(false);
            GlobalState.config.setDebug(false);
            String[] checkers = {"BVFinder"};
            Arrays.stream(checkers)
                    .filter(CheckerManager::hasChecker)
                    .forEach(GlobalState.config::addChecker);
        }
        if (!Logging.init()) {
            return;
        }

        FunctionModelManager.initAll();
        if (GlobalState.config.isEnableZ3() && !Utils.checkZ3Installation()) {
            return;
        }
        Logging.info("Preparing the program");
        if (!prepareProgram()) {
            Logging.error("Failed to prepare the program");
            return;
        }
        if (isRunningHeadless()) {
            if (!Utils.registerExternalFunctionsConfig(GlobalState.currentProgram, GlobalState.config)) {
                return;
            }
        } else {
            Utils.loadCustomExternalFunctionFromLabelHistory(GlobalState.currentProgram);
        }
        GlobalState.arch = new Architecture(GlobalState.currentProgram);
        boolean success = analyze();
        if (!success) {
            Logging.error("Failed to analyze the program: no entrypoint.");
            return;
        }
        Logging.info("Running checkers");
        CheckerManager.runCheckers(GlobalState.config);
        guiProcessResult();
        GlobalState.reset();
    }
}
