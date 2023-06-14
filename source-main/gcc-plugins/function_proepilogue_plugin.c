#include <stdio.h>
#include "gcc-common.h"
#include "tree.h"
#include "c-tree.h"
#include "cgraph.h"

// Debugging
#define PRINT_DEBUG 1
#define DEBUG_OUTPUT(str, args...) \
    if(PRINT_DEBUG) {fprintf(stderr, str, args);} \

// Macros to help output asm instructions to file
#define OUTPUT_INSN(str, file) fputs("\t", file); fputs(str, file); fputs(";\n", file)
#define OUTPUT_PUSH_RBP_INSN(file) OUTPUT_INSN("push %rbp", file)
#define OUTPUT_POP_RBP_INSN(file) OUTPUT_INSN("pop %rbp", file)
#define OUTPUT_RETQ_INSN(file) OUTPUT_INSN("retq", file)

// Macros to help overwrite instructions
#define OVERWRITE_INSN(insn_len) fseek(file, -insn_len, SEEK_CUR);
#define RETQ_INSN_LEN 5
#define LEAVEQ_INSN_LEN 7
#define POP_RBP_INSN_LEN 11

// Macros to write prologue/epilogue
// 通过rip寻址的方式将key的地址加载到R11寄存器中， key是一个标识符 
// 将r11寄存器的值与rsp做异或，然后取值
#define OUTPUT_R11_PROEPILOGUE(file) \
    OUTPUT_INSN("mov key@GOTPCREL(%rip), %r11", file); \
    OUTPUT_INSN("xor %r11, (%rsp)", file) \

// 将key的全局偏移表项（通过PC相对寻址）加载到rbp的寄存器中
// 将rbp寄存器的值与rsp寄存器相对于偏移8的内存位置进行异或操作
#define OUTPUT_RBP_PROEPILOGUE(file) \
    OUTPUT_INSN("mov key@GOTPCREL(%rip), %rbp", file); \
    OUTPUT_INSN("xor %rbp, 8(%rsp)", file) \

// Store some statistics about how many functions were changed
typedef struct plugin_statistics {
    int num_functions;
    int num_static_functions;
    int num_nonstatic_functions;
    int num_functions_with_frame_pointer_added;
} plugin_statistics;

plugin_statistics *ps = (plugin_statistics *) xmalloc(sizeof(plugin_statistics));


/* All plugins must export this symbol so that they can be linked with
   GCC license-wise.  */
int plugin_is_GPL_compatible;

static struct plugin_info function_proepilogue_plugin_info = {
        .version    = "1",
        .help        = "Add function prologues and epilogues\n",
};

// Is the current function static?
static bool is_static() {
    // 检查当前编译的函数是否为static，如果是static就为true，否则为false
    return !TREE_PUBLIC(current_function_decl);
}

/* Determine if rtx operation is on rbp register */
static bool is_rbp_register_operation(rtx body, int reg_op_num) {
    // 先获取寄存器号，然后获得寄存器的名字，判断是否是rbp寄存器
    const char *reg_name = reg_names[REGNO(XEXP(body, reg_op_num))];
    return strcmp(reg_name, "bp") == 0;
}

static bool is_retq_insn(rtx_insn *insn) {
    // 检查是否是一个跳转指令
    if (JUMP_P(insn)) {
        // 检查是否是一个函数返回操作
        rtx jump_insn = ((rtx_jump_insn *) insn)->jump_label();
        return (ANY_RETURN_P(jump_insn));
    }
    return false;
}

// 判断指令是否是push rbp的操作
static bool is_push_rbp_insn(rtx_insn *insn) {
    // 判断当前指令是否与函数栈帧相关，如果不想关则返回false
    if (insn->frame_related) {
        // 获得指令的模式
        rtx body = PATTERN(insn);

        // 判断当前代码是否是set操作
        if (GET_CODE(body) == SET) {
            rtx_code op0 = GET_CODE(XEXP(body, 0));
            rtx_code op1 = GET_CODE(XEXP(body, 1));

            // 如果该指令代码类型是MEM，op1的类型是寄存器，并且是操作rbp寄存器的，则返回true
            // Test for push %rbp instructions (should find at beginning of functions)
            return (op0 == MEM && op1 == REG && is_rbp_register_operation(body, 1));
        }
    }
    return false;
}


// 判断是否是pop rbp的指令
static bool is_final_pop_rbp_insn(rtx_insn *insn) {
    if (insn == NULL) return false;
    if (insn->frame_related) {
        rtx body = PATTERN(insn);

        if (GET_CODE(body) == SET) {
            rtx_code op0 = GET_CODE(XEXP(body, 0));
            rtx_code op1 = GET_CODE(XEXP(body, 1));

            // Test for pop %rbp instruction, should find at end of functions
            if (op0 == REG && op1 == MEM && is_rbp_register_operation(body, 0)) {
                rtx_insn *next_insn = next_real_insn(insn);
                return (is_retq_insn(next_insn));
            }
        }
    }
    return false;
}

static bool is_leaveq_insn(rtx_insn *insn) {
    if (insn == NULL) return false;
    // 取指令的模式
    rtx body = PATTERN(insn);

    // 查看代码是否为并行指令，其中包含多个子指令
    if (GET_CODE(body) == PARALLEL) {
        rtx op0 = XVECEXP(body, 0, 0);
        rtx op1 = XVECEXP(body, 0, 1);

        // op0是SET操作，第一个寄存器是reg，op1的代码类型也是reg, 并且是对rbp寄存器的操作
        return ((GET_CODE(op0) == SET) && GET_CODE(XEXP(op0, 0)) == REG && GET_CODE(XEXP(op1, 0)) == REG &&
            is_rbp_register_operation(op1, 0));
    }
    return false;
}

void function_prologue(FILE *file) {
    DEBUG_OUTPUT("%s static file \n", __func__);
    // 函数个数增加
    ps->num_functions++;

    if (is_static()) {
        // 静态函数增加
        ps->num_static_functions++;

        if (!is_push_rbp_insn(next_real_insn(entry_of_function()))) {
            // frame pointer指的栈帧，rbp之类的
            ps->num_functions_with_frame_pointer_added++;

            // push rbp
            OUTPUT_PUSH_RBP_INSN(file);
            // 从got中记载rbp并取异或值
            OUTPUT_RBP_PROEPILOGUE(file);
            // pop rbp值
            OUTPUT_POP_RBP_INSN(file);
        }
    }
    else {
        ps->num_nonstatic_functions++;

        // 加载rsp的操作
        OUTPUT_R11_PROEPILOGUE(file);
    }
}

// Handle instructions from non-static functions
void final_postscan_insn_nonstatic(rtx_insn *insn, FILE *file) {
    // In the case where we already have an final push %rbp, add the rbp epilogue before it
    // 如果是函数收尾的pop rbp操作
    if (is_final_pop_rbp_insn(insn)) {
        OUTPUT_R11_PROEPILOGUE(file);
    }

    // 如果retq指令前面是有一个pop rbp操作
    // If we find a retq without a %pop rbp before it
    else if (is_retq_insn(insn) && !is_final_pop_rbp_insn(prev_real_insn(insn))) {
        OVERWRITE_INSN(RETQ_INSN_LEN);
        // 加载rsp操作
        OUTPUT_R11_PROEPILOGUE(file);
        // 执行retq操作
        OUTPUT_RETQ_INSN(file);
    }

}

// Handle instructions from static functions
// prev_real_insn是在指定的汇编指令insn之前找到一个实际指令（非调试或填充）
void final_postscan_insn_static(rtx_insn *insn, FILE *file) {
    // In the case where we already have an initial push %rbp, just add the rbp prologue after it
    // 判断当前指令是否是 push %rbp指令，并且前面是否存在一个实际指令，如果不存在实际指令
    if (is_push_rbp_insn(insn) && !prev_real_insn(insn)) {
        // 栈中加入值
        OUTPUT_RBP_PROEPILOGUE(file);
    }

    //Convert leaveq instructions
    // 如果是并行指令，并且是对寄存器的操作，且最后一个指令操作的是rbp寄存器
    // leaveq指令是在函数返回清理栈帧，是两条指令的合并, mov rbp->rsp,  pop rbq
    else if (is_leaveq_insn(insn)) {
        //  重新写leaveq指令, OVERWRITE_INSN用来fseek函数位置
        OVERWRITE_INSN(LEAVEQ_INSN_LEN)// overwrite leaveq instruction

        // 将rbp的指令赋值给rsp
        OUTPUT_INSN("mov %rbp, %rsp", file);
        // 从GOT表中读取rbp的地址，赋值给rbp，然后rsp和rbp的值取异或
        // 异或应该是加密的方式
        OUTPUT_RBP_PROEPILOGUE(file);
        OUTPUT_POP_RBP_INSN(file);
    }

    // In the case where we already have an final push %rbp, add the rbp epilogue before it
    // 如果是函数收尾的pop rbp操作
    else if (is_final_pop_rbp_insn(insn)) {
        OVERWRITE_INSN(POP_RBP_INSN_LEN);
        
        // 从GOT表中读取rbp的地址，赋值给rbp，然后rsp和rbp的值取异或
        // 异或应该是加密的方式
        OUTPUT_RBP_PROEPILOGUE(file);
        OUTPUT_POP_RBP_INSN(file);
    }

        // If we find a retq without a %pop rbp before it
        // 如果是retq指令，用于函数返回操作。将程序的控制权从函数内部返回到调用函数的位置
        // 如果指令的前一条实际指令不是函数收尾的pop rbp操作
        // 如果指令的前一条实际指令不是leaveq指令
    else if (is_retq_insn(insn) && !is_final_pop_rbp_insn(prev_real_insn(insn)) && !is_leaveq_insn(prev_real_insn(insn))) {
        OVERWRITE_INSN(RETQ_INSN_LEN); // Overwrite retq insn

        // push rbp操作
        OUTPUT_PUSH_RBP_INSN(file);
        // 从GOT中加载rbp,并且取异或值
        OUTPUT_RBP_PROEPILOGUE(file);
        //  pop rbp操作 
        OUTPUT_POP_RBP_INSN(file);
        // retq指令
        OUTPUT_RETQ_INSN(file); //Re-write retq
    }
}

/* Called after each instruction that is output.
 * Look for push/pop %rbp and overwrite. */
// 根据是否为静态判断内容，这里的静态指的是什么？
void final_postscan_insn(FILE *file, rtx_insn *insn, rtx *opvec, int noperands) {
    is_static() ? final_postscan_insn_static(insn, file) : final_postscan_insn_nonstatic(insn, file);
}


/* Add gcc target hooks for asm generation */
static void function_proepilogue_start_unit(void *gcc_data, void *user_data) {
    // 表示汇编代码生成阶段的最后扫描指令处理函数。负责对汇编代码中的指令进行处理，进行一定特定的操作或优化
    targetm.asm_out.final_postscan_insn = final_postscan_insn;
    // 表示用于生成函数前导代码的函数指针，指向的函数用于生成函数的前导代码。
    // 前导代码是在函数的入口处插入的一段汇百年代码，用于进行函数的初始化和准备工作哦，记录保存寄存器状态、分配栈空间等
    targetm.asm_out.function_prologue = function_prologue;
}


/* Main function, don't need to do anything here right now. */
static unsigned int function_proepilogue_instrument_execute(void) {
    return 0;
}

// Print out statistics found during compilation with plugin
static void function_proepilogue_finish(void *gcc_data, void *user_data) {
    DEBUG_OUTPUT("Number of functions: %d\n", ps->num_functions);
    DEBUG_OUTPUT("Number of non-static functions: %d (%2.1f%% of functions)\n", ps->num_nonstatic_functions,
                 ((float) ps->num_nonstatic_functions / ps->num_functions) * 100);
    DEBUG_OUTPUT("Number of static functions: %d (%2.1f%% of functions)\n", ps->num_static_functions,
                 ((float) ps->num_static_functions / ps->num_functions) * 100);
    DEBUG_OUTPUT("Number of functions with push/pop %rbp added: %d (%2.1f%% of static functions)\n",
                 ps->num_functions_with_frame_pointer_added,
                 ((float) ps->num_functions_with_frame_pointer_added / ps->num_static_functions) * 100);
    DEBUG_OUTPUT("\n\n\n\n", "");
}


#define PASS_NAME function_proepilogue_instrument
#define NO_GATE

#include "gcc-generate-rtl-pass.h"


__visible int
plugin_init(struct plugin_name_args *plugin_info,
            struct plugin_gcc_version *version) {

    const char *const plugin_name = plugin_info->base_name;

    // Initialize statistics
    ps->num_functions = 0;
    ps->num_static_functions = 0;
    ps->num_nonstatic_functions = 0;
    ps->num_functions_with_frame_pointer_added = 0;

    if (!plugin_default_version_check(version, &gcc_version)) {
        error(G_("incompatible gcc/plugin versions"));
        return 1;
    }

    // 对编译器进行expand操作
    PASS_INFO(function_proepilogue_instrument, "expand", 1, PASS_POS_INSERT_AFTER);

    // 插件信息
    register_callback(plugin_name, PLUGIN_INFO, NULL,
                      &function_proepilogue_plugin_info);

    // 没有执行任何操作
    register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
                      &function_proepilogue_instrument_pass_info);

    // 有问题
    register_callback(plugin_name, PLUGIN_START_UNIT,
                      function_proepilogue_start_unit, NULL);

    // 输出函数的信息内容，进行统计
    register_callback(plugin_name, PLUGIN_FINISH,
                      function_proepilogue_finish, NULL);


    return 0;
}
