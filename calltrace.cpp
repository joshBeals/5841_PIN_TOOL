#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include <set>
using std::hex;
using std::cerr;
using std::string;
using std::ios;
using std::endl;

std::ofstream TraceFile;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "calltrace.out", "specify trace file name");
KNOB<BOOL> KnobPrintArgs(KNOB_MODE_WRITEONCE, "pintool", "a", "0", "print call arguments");

// Map to keep track of routine call counts
std::map<string, UINT64> routineCallCount;

INT32 Usage()
{
    cerr << "This tool produces a call trace." << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

const string invalid = "invalid_rtn";

const string *Target2String(ADDRINT target)
{
    string name = RTN_FindNameByAddress(target);
    if (name == "")
        return &invalid;
    else
        return new string(name);
}

VOID do_call_args(const string *s, ADDRINT arg0)
{
    TraceFile << *s << "(" << arg0 << ",...)" << endl;
    routineCallCount[*s]++; // Increment the call count for this routine
}

VOID do_call_args_indirect(ADDRINT target, BOOL taken, ADDRINT arg0)
{
    if (!taken)
        return;

    const string *s = Target2String(target);
    do_call_args(s, arg0);

    if (s != &invalid)
        delete s;
}

VOID do_call(const string *s)
{
    routineCallCount[*s]++; // Increment the call count for this routine
}

VOID do_call_indirect(ADDRINT target, BOOL taken)
{
    if (!taken)
        return;

    const string *s = Target2String(target);
    do_call(s);

    if (s != &invalid)
        delete s;
}

VOID Trace(TRACE trace, VOID *v)
{
    const BOOL print_args = KnobPrintArgs.Value();

    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        INS tail = BBL_InsTail(bbl);

        if (INS_IsCall(tail))
        {
            if (INS_IsDirectControlFlow(tail))
            {
                const ADDRINT target = INS_DirectControlFlowTargetAddress(tail);
                if (print_args)
                {
                    INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args),
                                             IARG_PTR, Target2String(target), IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_END);
                }
                else
                {
                    INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_call),
                                             IARG_PTR, Target2String(target), IARG_END);
                }
            }
            else
            {
                if (print_args)
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_END);
                }
                else
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
                }
            }
        }
        else
        {
            RTN rtn = TRACE_Rtn(trace);

            if (RTN_Valid(rtn) && !INS_IsDirectControlFlow(tail) && ".plt" == SEC_Name(RTN_Sec(rtn)))
            {
                if (print_args)
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_args_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_END);
                }
                else
                {
                    INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
                }
            }
        }
    }
}

VOID Fini(INT32 code, VOID *v)
{
    string mostFrequentRoutine;
    UINT64 highestCallCount = 0;
    UINT64 totalCalls = 0;

    // Print the routine names and their call counts
    TraceFile << std::left << std::setw(10) << "Call Count" << "\t" << "Routine" << endl;
    for (const auto &entry : routineCallCount)
    {
        if (entry.second > highestCallCount)
        {
            highestCallCount = entry.second;
            mostFrequentRoutine = entry.first;
        }

        totalCalls += entry.second;

        TraceFile << std::left << std::setw(10) << std::dec << entry.second << "\t" << entry.first << endl;
    }

    float perc = (highestCallCount * 1.0 / totalCalls) * 100;

    TraceFile << "\n\n************** FINAL ANALYSIS ****************\n" << endl;

    TraceFile << "Total routine calls: " << totalCalls << "\n" << endl;

    TraceFile << "The most frequently called routine is: " << mostFrequentRoutine << " with count of: " << std::dec << highestCallCount << "\n" << endl;

    TraceFile << "Percentage of execution of " << mostFrequentRoutine << " = " << perc << "%\n" << endl;

    TraceFile << "***********************************************\n\n" << endl;

    TraceFile << "# eof" << endl;

    TraceFile.close();
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    TraceFile.open(KnobOutputFile.Value().c_str());

    TraceFile << hex;
    TraceFile.setf(ios::showbase);

    string trace_header = string("#\n"
                                 "# Call Trace Generated By Pin\n"
                                 "#\n");

    TraceFile.write(trace_header.c_str(), trace_header.size());

    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
